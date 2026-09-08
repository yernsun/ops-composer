from __future__ import annotations

import asyncio
import os
import shutil
import signal
import tempfile
from contextlib import suppress
from pathlib import Path


class SshAgentStartError(RuntimeError):
    """Safe marker for failures while loading a private key into an ephemeral agent."""


class EphemeralSshAgent:
    def __init__(
        self,
        process: asyncio.subprocess.Process,
        socket_path: Path,
        runtime_path: Path,
        socket_runtime_path: Path,
    ) -> None:
        self._process = process
        self.socket_path = socket_path
        self.runtime_path = runtime_path
        self._socket_runtime_path = socket_runtime_path
        self._closed = False

    @classmethod
    async def start(
        cls,
        runtime_path: Path,
        private_key: str,
        passphrase: str | None,
    ) -> EphemeralSshAgent:
        runtime_path.mkdir(mode=0o700, parents=True, exist_ok=False)
        runtime_path.chmod(0o700)
        key_path = runtime_path / "identity"
        socket_runtime_path = runtime_path
        socket_path = socket_runtime_path / "agent.sock"
        if len(os.fsencode(socket_path)) >= 100:
            socket_runtime_path = Path(tempfile.mkdtemp(prefix="ops-composer-agent-"))
            socket_runtime_path.chmod(0o700)
            socket_path = socket_runtime_path / "agent.sock"
        process: asyncio.subprocess.Process | None = None
        try:
            key_fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                payload = memoryview(private_key.encode("utf-8"))
                while payload:
                    payload = payload[os.write(key_fd, payload) :]
            finally:
                os.close(key_fd)

            process = await asyncio.create_subprocess_exec(
                "ssh-agent",
                "-D",
                "-a",
                str(socket_path),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
            )
            for _ in range(100):
                if socket_path.exists():
                    break
                if process.returncode is not None:
                    raise SshAgentStartError("ssh-agent exited before creating its socket")
                await asyncio.sleep(0.01)
            else:
                raise SshAgentStartError("ssh-agent did not create its socket")

            await cls._add_identity(socket_path, key_path, runtime_path, passphrase)
            key_path.unlink(missing_ok=True)
            return cls(process, socket_path, runtime_path, socket_runtime_path)
        except Exception as error:
            key_path.unlink(missing_ok=True)
            if process is not None and process.returncode is None:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                await process.wait()
            if runtime_path.is_dir():
                shutil.rmtree(runtime_path)
            if socket_runtime_path != runtime_path and socket_runtime_path.is_dir():
                shutil.rmtree(socket_runtime_path)
            if isinstance(error, SshAgentStartError):
                raise
            raise SshAgentStartError("SSH private key could not be loaded") from error

    @staticmethod
    async def _add_identity(
        socket_path: Path,
        key_path: Path,
        runtime_path: Path,
        passphrase: str | None,
    ) -> None:
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "SSH_AUTH_SOCK": str(socket_path),
        }
        read_fd = -1
        write_fd = -1
        pass_fds: tuple[int, ...] = ()
        if passphrase is not None:
            helper_path = runtime_path / "askpass"
            helper_fd = os.open(helper_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o700)
            try:
                helper = (
                    b"#!/usr/bin/env python3\n"
                    b"import os\n"
                    b"descriptor = int(os.environ['OPS_COMPOSER_ASKPASS_FD'])\n"
                    b"while payload := os.read(descriptor, 65536):\n"
                    b"    os.write(1, payload)\n"
                )
                os.write(helper_fd, helper)
            finally:
                os.close(helper_fd)
            read_fd, write_fd = os.pipe()
            os.set_inheritable(read_fd, True)
            environment.update(
                {
                    "DISPLAY": "ops-composer:0",
                    "SSH_ASKPASS": str(helper_path),
                    "SSH_ASKPASS_REQUIRE": "force",
                    "OPS_COMPOSER_ASKPASS_FD": str(read_fd),
                }
            )
            pass_fds = (read_fd,)
        try:
            add_process = await asyncio.create_subprocess_exec(
                "ssh-add",
                str(key_path),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                close_fds=True,
                pass_fds=pass_fds,
                env=environment,
            )
            if read_fd >= 0:
                os.close(read_fd)
                read_fd = -1
            if write_fd >= 0:
                assert passphrase is not None
                payload = memoryview(passphrase.encode("utf-8") + b"\n")
                while payload:
                    payload = payload[os.write(write_fd, payload) :]
                os.close(write_fd)
                write_fd = -1
            if await add_process.wait() != 0:
                raise SshAgentStartError("SSH private key could not be loaded")
        finally:
            for descriptor in (read_fd, write_fd):
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._process.returncode is None:
            for process_signal in (signal.SIGTERM, signal.SIGKILL):
                with suppress(ProcessLookupError):
                    os.killpg(self._process.pid, process_signal)
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=1)
                    break
                except TimeoutError:
                    continue
        parent = self.runtime_path.parent
        if self.runtime_path.is_dir() and self.runtime_path.parent == parent:
            shutil.rmtree(self.runtime_path)
        if (
            self._socket_runtime_path != self.runtime_path
            and self._socket_runtime_path.is_dir()
        ):
            shutil.rmtree(self._socket_runtime_path)
