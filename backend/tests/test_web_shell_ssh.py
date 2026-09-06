from __future__ import annotations

import asyncio
import os
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import SecretStr

from ops_composer.domain.base import utc_now
from ops_composer.domain.web_shell import WebShellLaunch, WebShellSession, WebShellState
from ops_composer.ssh_terminal import SshTerminal


def _ssh_settings() -> tuple[str, int, str]:
    password = os.getenv("TEST_SSH_PASSWORD")
    if not password:
        pytest.skip("set TEST_SSH_PASSWORD to run Web Shell SSH integration tests")
    return os.getenv("TEST_SSH_ADDRESS", "127.0.0.1"), int(
        os.getenv("TEST_SSH_PORT", "22222")
    ), password


async def _scan_key(address: str, port: int) -> str:
    process = await asyncio.create_subprocess_exec(
        "ssh-keyscan",
        "-T",
        "5",
        "-p",
        str(port),
        address,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await process.communicate()
    assert process.returncode == 0
    lines = [line for line in stdout.decode().splitlines() if line and not line.startswith("#")]
    assert lines
    return "\n".join(lines) + "\n"


def _launch(address: str, port: int, password: str, known_hosts: str) -> WebShellLaunch:
    now = utc_now()
    session = WebShellSession(
        web_shell_session_id=uuid4(),
        host_id=uuid4(),
        actor_user_id=uuid4(),
        auth_session_id=uuid4(),
        credential_id=uuid4(),
        credential_version=1,
        host_name="ssh-integration",
        host_address=address,
        ssh_port=port,
        username="opsrunner",
        state=WebShellState.ACTIVE,
        api_instance_id="ssh-integration",
        owner_id="ssh-integration:stream",
        ticket_expires_at=now + timedelta(seconds=30),
        lease_expires_at=now + timedelta(seconds=30),
        connected_at=now,
        last_activity_at=now,
        created_at=now,
    )
    return WebShellLaunch(
        session=session,
        password=SecretStr(password),
        known_hosts=known_hosts,
    )


async def _read_until(
    terminal: SshTerminal,
    expected: bytes,
    *,
    timeout: float = 15,
) -> bytes:
    output = bytearray()

    async def consume() -> bytes:
        while expected not in output:
            chunk = await terminal.read(64 * 1024)
            if not chunk:
                break
            output.extend(chunk)
        return bytes(output)

    return await asyncio.wait_for(consume(), timeout=timeout)


@pytest.mark.asyncio
async def test_real_ssh_pty_resize_ctrl_c_and_cleanup(tmp_path: Path) -> None:
    address, port, password = _ssh_settings()
    known_hosts = await _scan_key(address, port)
    launch = _launch(address, port, password, known_hosts)
    terminal = await SshTerminal.start(launch, tmp_path)
    runtime_path = tmp_path / "web-shell" / str(launch.session.web_shell_session_id)
    remote_marker = f"/tmp/ops-composer-web-shell-{uuid4().hex}.closed"
    try:
        await terminal.write(b"printf 'WEB_SHELL_READY\\n'; stty size\n")
        output = await _read_until(terminal, b"30 120")
        assert b"WEB_SHELL_READY" in output
        assert b"30 120" in output

        terminal.resize(100, 42)
        # OpenSSH forwards SIGWINCH asynchronously over the SSH channel.
        await asyncio.sleep(0.2)
        await terminal.write(b"stty size; printf 'RESIZED\\n'\n")
        resized = await _read_until(terminal, b"\r\nRESIZED\r\n")
        assert b"42 100" in resized

        await terminal.write(b"sleep 30\n")
        await asyncio.sleep(0.2)
        await terminal.write(b"\x03")
        await asyncio.sleep(0.2)
        await terminal.write(b"printf 'INTERRUPTED\\n'\n")
        interrupted = await _read_until(terminal, b"INTERRUPTED\r\n")
        assert b"INTERRUPTED" in interrupted

        await terminal.write(
            (
                "sleep 30 & child=$!; "
                f"printf '%s %s\\n' \"$$\" \"$child\" > {remote_marker}; "
                "printf 'REMOTE_PROCESS_READY\\n'; wait \"$child\"\n"
            ).encode()
        )
        await _read_until(terminal, b"REMOTE_PROCESS_READY\r\n")
    finally:
        await terminal.close()
    assert not runtime_path.exists()

    verification = await SshTerminal.start(
        _launch(address, port, password, known_hosts), tmp_path
    )
    try:
        await verification.write(
            (
                f"read shell_pid child_pid < {remote_marker}; "
                "status=ALIVE; for i in $(seq 1 30); do "
                "if ! kill -0 \"$shell_pid\" 2>/dev/null && "
                "! kill -0 \"$child_pid\" 2>/dev/null; then status=STOPPED; break; fi; "
                "sleep 0.1; done; "
                f"rm -f {remote_marker}; printf 'STATUS:%s\\n' \"$status\"; "
                "printf 'CHECK_COMPLETE\\n'\n"
            ).encode()
        )
        cleanup = await _read_until(verification, b"CHECK_COMPLETE\r\n")
        assert b"STATUS:STOPPED\r\n" in cleanup
    finally:
        await verification.close()


@pytest.mark.asyncio
async def test_real_ssh_wrong_password_fails_closed(tmp_path: Path) -> None:
    address, port, _password = _ssh_settings()
    known_hosts = await _scan_key(address, port)
    launch = _launch(address, port, "intentionally-wrong-password", known_hosts)
    terminal = await SshTerminal.start(launch, tmp_path)
    try:
        assert await asyncio.wait_for(terminal.wait(), timeout=20) == 255
    finally:
        await terminal.close()
