from __future__ import annotations

import asyncio
import errno
import fcntl
import os
import pty
import shutil
import signal
import struct
import termios
from contextlib import suppress
from pathlib import Path

from ops_composer.domain.web_shell import WebShellLaunch

DEFAULT_COLUMNS = 120
DEFAULT_ROWS = 30
SSH_CONNECT_TIMEOUT_SECONDS = 15


class SshTerminalStartError(RuntimeError):
    """A safe marker for local SSH/PTY startup failures."""


class SshTerminal:
    def __init__(
        self,
        process: asyncio.subprocess.Process,
        master_fd: int,
        runtime_path: Path,
    ) -> None:
        self._process = process
        self._master_fd = master_fd
        self._runtime_path = runtime_path
        self._close_lock = asyncio.Lock()
        self._closed = False

    @classmethod
    async def start(
        cls,
        launch: WebShellLaunch,
        runtime_root: Path,
        *,
        columns: int = DEFAULT_COLUMNS,
        rows: int = DEFAULT_ROWS,
    ) -> SshTerminal:
        shell_root = (runtime_root / "web-shell").resolve()
        runtime_path = shell_root / str(launch.session.web_shell_session_id)
        shell_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        shell_root.chmod(0o700)
        if runtime_path.exists():
            shutil.rmtree(runtime_path)
        runtime_path.mkdir(mode=0o700)
        known_hosts_path = runtime_path / "known_hosts"

        master_fd = -1
        slave_fd = -1
        password_read_fd = -1
        password_write_fd = -1
        process: asyncio.subprocess.Process | None = None
        try:
            known_hosts_fd = os.open(
                known_hosts_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            try:
                known_hosts = launch.known_hosts.encode("utf-8")
                while known_hosts:
                    written = os.write(known_hosts_fd, known_hosts)
                    known_hosts = known_hosts[written:]
            finally:
                os.close(known_hosts_fd)
            master_fd, slave_fd = pty.openpty()
            os.set_blocking(master_fd, False)
            cls._resize_fd(master_fd, columns, rows)
            password_read_fd, password_write_fd = os.pipe()
            os.set_inheritable(password_read_fd, True)
            minimal_environment = {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "TERM": "xterm-256color",
                "LANG": "C.UTF-8",
            }
            process = await asyncio.create_subprocess_exec(
                "setsid",
                "--ctty",
                "sshpass",
                "-d",
                str(password_read_fd),
                "ssh",
                "-F",
                "/dev/null",
                "-tt",
                "-l",
                launch.session.username,
                "-p",
                str(launch.session.ssh_port),
                "-o",
                f"UserKnownHostsFile={known_hosts_path}",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "BatchMode=no",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "PasswordAuthentication=yes",
                "-o",
                "KbdInteractiveAuthentication=yes",
                "-o",
                "PreferredAuthentications=password,keyboard-interactive",
                "-o",
                "NumberOfPasswordPrompts=1",
                "-o",
                f"ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                launch.session.host_address,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                pass_fds=(password_read_fd,),
                env=minimal_environment,
            )
            os.close(slave_fd)
            slave_fd = -1
            os.close(password_read_fd)
            password_read_fd = -1
            password_bytes = memoryview(
                launch.password.get_secret_value().encode("utf-8") + b"\n"
            )
            while password_bytes:
                password_bytes = password_bytes[os.write(password_write_fd, password_bytes) :]
            os.close(password_write_fd)
            password_write_fd = -1
            return cls(process, master_fd, runtime_path)
        except Exception as error:
            for descriptor in (slave_fd, password_read_fd, password_write_fd, master_fd):
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            if runtime_path.is_dir() and runtime_path.parent == shell_root:
                shutil.rmtree(runtime_path)
            raise SshTerminalStartError("local SSH terminal startup failed") from error

    @staticmethod
    def _resize_fd(descriptor: int, columns: int, rows: int) -> None:
        dimensions = struct.pack("HHHH", rows, columns, 0, 0)
        fcntl.ioctl(descriptor, termios.TIOCSWINSZ, dimensions)

    async def _wait_readable(self) -> None:
        loop = asyncio.get_running_loop()
        ready: asyncio.Future[None] = loop.create_future()

        def mark_ready() -> None:
            if not ready.done():
                ready.set_result(None)

        loop.add_reader(self._master_fd, mark_ready)
        try:
            await ready
        finally:
            loop.remove_reader(self._master_fd)

    async def _wait_writable(self) -> None:
        loop = asyncio.get_running_loop()
        ready: asyncio.Future[None] = loop.create_future()

        def mark_ready() -> None:
            if not ready.done():
                ready.set_result(None)

        loop.add_writer(self._master_fd, mark_ready)
        try:
            await ready
        finally:
            loop.remove_writer(self._master_fd)

    async def read(self, maximum_bytes: int) -> bytes:
        while not self._closed:
            try:
                return os.read(self._master_fd, maximum_bytes)
            except BlockingIOError:
                await self._wait_readable()
            except OSError as error:
                if error.errno in {errno.EBADF, errno.EIO}:
                    return b""
                raise
        return b""

    async def write(self, data: bytes) -> None:
        view = memoryview(data)
        while view and not self._closed:
            try:
                written = os.write(self._master_fd, view)
                view = view[written:]
            except BlockingIOError:
                await self._wait_writable()
            except OSError as error:
                if error.errno in {errno.EBADF, errno.EIO}:
                    return
                raise

    def resize(self, columns: int, rows: int) -> None:
        if not self._closed:
            self._resize_fd(self._master_fd, columns, rows)
            # OpenSSH watches SIGWINCH on its controlling PTY and forwards the
            # updated dimensions to the remote terminal.
            with suppress(ProcessLookupError):
                os.killpg(self._process.pid, signal.SIGWINCH)

    async def wait(self) -> int:
        return await self._process.wait()

    @property
    def returncode(self) -> int | None:
        return self._process.returncode

    async def close(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            self._closed = True
            # Closing the browser-facing PTY first gives the nested OpenSSH
            # child (sshpass owns a helper PTY/session) an EOF, so it closes
            # the TCP connection and sshd tears down the remote foreground
            # process. Signalling only sshpass's outer process group can leave
            # that nested SSH process orphaned.
            with suppress(OSError):
                os.close(self._master_fd)
            if self._process.returncode is None:
                with suppress(TimeoutError):
                    await asyncio.wait_for(self._process.wait(), timeout=1)
            if self._process.returncode is None:
                for process_signal in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.killpg(self._process.pid, process_signal)
                    except ProcessLookupError:
                        break
                    try:
                        await asyncio.wait_for(self._process.wait(), timeout=1)
                        break
                    except TimeoutError:
                        continue
            shell_root = self._runtime_path.parent
            if self._runtime_path.is_dir() and self._runtime_path.parent == shell_root:
                shutil.rmtree(self._runtime_path)
