from __future__ import annotations

import asyncio
import os
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

import pytest

import ops_composer.ssh_agent as ssh_agent_module
from ops_composer.ssh_agent import EphemeralSshAgent, SshAgentStartError


class _Process:
    def __init__(self, *, return_code: int | None = None, wait_result: int = 0) -> None:
        self.returncode = return_code
        self.wait_result = wait_result
        self.pid = 43210
        self.wait_calls = 0

    async def wait(self) -> int:
        self.wait_calls += 1
        self.returncode = self.wait_result
        return self.wait_result


def _mock_processes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    agent_return_code: int | None = None,
    add_return_code: int = 0,
) -> tuple[_Process, list[tuple[tuple[object, ...], dict[str, object]]]]:
    agent = _Process(return_code=agent_return_code)
    add = _Process(wait_result=add_return_code)
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    async def create_subprocess_exec(
        *arguments: object, **options: object
    ) -> _Process:
        calls.append((arguments, options))
        return agent if arguments[0] == "ssh-agent" else add

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_subprocess_exec)
    return agent, calls


@pytest.mark.asyncio
@pytest.mark.parametrize("passphrase", [None, "test passphrase with spaces !@#"])
async def test_ephemeral_ssh_agent_loads_key_and_cleans_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    passphrase: str | None,
) -> None:
    agent_process, calls = _mock_processes(monkeypatch)
    original_exists = Path.exists
    monkeypatch.setattr(
        Path,
        "exists",
        lambda path: True if path.name == "agent.sock" else original_exists(path),
    )
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "killpg", lambda pid, sig: killed.append((pid, sig)))

    original_write = os.write
    original_close = os.close
    fake_descriptors = {987, 988}
    pipe_payloads: list[bytes] = []
    if passphrase is not None:
        monkeypatch.setattr(os, "pipe", lambda: (987, 988))
        monkeypatch.setattr(os, "set_inheritable", lambda _fd, _value: None)

        def safe_write(descriptor: int, payload: bytes | memoryview[bytes]) -> int:
            if descriptor in fake_descriptors:
                pipe_payloads.append(bytes(payload))
                return len(payload)
            return original_write(descriptor, payload)

        monkeypatch.setattr(os, "write", safe_write)
        monkeypatch.setattr(
            os,
            "close",
            lambda descriptor: None
            if descriptor in fake_descriptors
            else original_close(descriptor),
        )

    runtime = tmp_path / ("long-runtime-component-" * 5) / "agent"
    agent = await EphemeralSshAgent.start(runtime, "PRIVATE-KEY-SENTINEL", passphrase)

    assert len(calls) == 2
    assert calls[0][0][:3] == ("ssh-agent", "-D", "-a")
    assert calls[1][0] == ("ssh-add", str(runtime / "identity"))
    assert calls[0][1]["start_new_session"] is True
    assert "PRIVATE-KEY-SENTINEL" not in repr(calls)
    if passphrase is not None:
        assert b"".join(pipe_payloads) == passphrase.encode("utf-8") + b"\n"
        assert calls[1][1]["pass_fds"] == (987,)
    assert not (runtime / "identity").exists()
    socket_runtime = agent.socket_path.parent

    await agent.close()
    await agent.close()

    assert killed
    assert agent_process.wait_calls == 1
    assert not runtime.exists()
    assert not socket_runtime.exists()


@pytest.mark.asyncio
async def test_ephemeral_ssh_agent_rejects_bad_key_and_cleans_process(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    agent_process, _calls = _mock_processes(monkeypatch, add_return_code=1)
    original_exists = Path.exists
    monkeypatch.setattr(
        Path,
        "exists",
        lambda path: True if path.name == "agent.sock" else original_exists(path),
    )
    killed: list[int] = []
    monkeypatch.setattr(os, "killpg", lambda pid, _sig: killed.append(pid))
    runtime = tmp_path / "invalid-agent"

    with pytest.raises(SshAgentStartError, match="could not be loaded"):
        await EphemeralSshAgent.start(runtime, "BAD-KEY-SENTINEL", None)

    assert killed == [agent_process.pid]
    assert agent_process.wait_calls == 1
    assert not runtime.exists()


@pytest.mark.asyncio
async def test_ephemeral_ssh_agent_reports_early_exit_and_socket_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(Path, "exists", lambda _path: False)
    exited, _calls = _mock_processes(monkeypatch, agent_return_code=1)
    with pytest.raises(SshAgentStartError, match="exited before"):
        await EphemeralSshAgent.start(tmp_path / "exited", "key", None)
    assert exited.wait_calls == 0

    waiting, _calls = _mock_processes(monkeypatch)

    async def no_delay(_seconds: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", no_delay)
    monkeypatch.setattr(os, "killpg", lambda _pid, _sig: None)
    with pytest.raises(SshAgentStartError, match="did not create"):
        await EphemeralSshAgent.start(tmp_path / "timeout", "key", None)
    assert waiting.wait_calls == 1


@pytest.mark.asyncio
async def test_ephemeral_ssh_agent_escalates_to_kill_after_close_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    process = _Process()
    runtime = tmp_path / "runtime"
    socket_runtime = tmp_path / "socket"
    runtime.mkdir()
    socket_runtime.mkdir()
    agent = EphemeralSshAgent(process, socket_runtime / "agent.sock", runtime, socket_runtime)
    waits = 0

    async def wait_for(
        awaitable: Coroutine[Any, Any, int], *, timeout: float
    ) -> int:
        nonlocal waits
        assert timeout == 1
        waits += 1
        if waits == 1:
            awaitable.close()
            raise TimeoutError
        return await awaitable

    signals: list[int] = []
    monkeypatch.setattr(asyncio, "wait_for", wait_for)
    monkeypatch.setattr(os, "killpg", lambda _pid, sig: signals.append(sig))

    await agent.close()

    assert signals == [ssh_agent_module.signal.SIGTERM, ssh_agent_module.signal.SIGKILL]
    assert not runtime.exists()
    assert not socket_runtime.exists()
