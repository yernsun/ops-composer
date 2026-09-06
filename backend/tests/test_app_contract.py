from ops_composer.main import app
from ops_composer.settings import Settings


def test_m1_openapi_contract_is_single_admin_and_complete() -> None:
    schema = app.openapi()
    paths = set(schema["paths"])
    expected = {
        "/health/live",
        "/health/ready",
        "/api/v1/auth/login",
        "/api/v1/auth/session",
        "/api/v1/auth/logout",
        "/api/v1/overview",
        "/api/v1/hosts",
        "/api/v1/hosts/{host_id}",
        "/api/v1/hosts/{host_id}/host-keys/scan",
        "/api/v1/hosts/{host_id}/host-keys/confirm",
        "/api/v1/hosts/{host_id}/web-shell-sessions",
        "/api/v1/groups",
        "/api/v1/groups/{group_id}",
        "/api/v1/credentials",
        "/api/v1/credentials/{credential_id}/revisions",
        "/api/v1/inventory/resolve",
        "/api/v1/inventory/preview",
        "/api/v1/playbooks",
        "/api/v1/playbooks/config",
        "/api/v1/playbooks/database",
        "/api/v1/playbooks/database/{playbook_id}",
        "/api/v1/playbooks/detail",
        "/api/v1/playbooks/validate",
        "/api/v1/runs/commands",
        "/api/v1/runs/playbooks",
        "/api/v1/runs/{run_id}",
        "/api/v1/runs/{run_id}/cancel",
        "/api/v1/runs/{run_id}/retry",
        "/api/v1/runs/{run_id}/events/stream",
        "/api/v1/system/info",
        "/api/v1/system/doctor",
        "/api/v1/web-shell-sessions/{web_shell_session_id}",
    }
    assert expected <= paths
    assert len(paths) == 38
    assert not any("signup" in path or "workspace" in path for path in paths)

    session = schema["components"]["schemas"]["SessionResponse"]["properties"]
    assert session["userId"]["format"] == "uuid"
    assert session["expiresAt"]["format"] == "date-time"
    assert "username" in session

    create_run = schema["paths"]["/api/v1/runs/commands"]["post"]
    assert create_run["operationId"] == "createCommandRun"
    assert "202" in create_run["responses"]
    assert any(
        parameter["name"] == "Idempotency-Key" and parameter["in"] == "header"
        for parameter in create_run["parameters"]
    )

    overview = schema["paths"]["/api/v1/overview"]["get"]
    overview_schema = overview["responses"]["200"]["content"]["application/json"]["schema"]
    assert overview_schema["$ref"] == "#/components/schemas/OverviewResponse"
    overview_properties = schema["components"]["schemas"]["OverviewResponse"]["properties"]
    assert set(overview_properties) == {
        "hostCount",
        "enabledHostCount",
        "runsToday",
        "failedRuns",
        "activeRuns",
    }

    login = schema["paths"]["/api/v1/auth/login"]["post"]
    assert login["operationId"] == "login"
    assert {"401", "403", "429"} <= login["responses"].keys()
    assert login["responses"]["429"]["headers"]["Retry-After"]["schema"]["type"] == "integer"


def test_settings_only_expose_postgresql_and_local_runtime_capabilities() -> None:
    fields = Settings.model_fields
    assert "database_url" in fields
    assert "master_key" in fields
    assert "playbook_workspace" in fields
    assert "playbook_source_mode" in fields
    assert "runtime_dir" in fields
    assert "web_shell_max_sessions" in fields
    assert "web_shell_idle_timeout_seconds" in fields
    assert "web_shell_max_duration_seconds" in fields
    assert "redis_url" not in fields
    assert "sqlite_path" not in fields
    assert "broker_url" not in fields


def test_operator_cli_exposes_bootstrap_worker_and_configuration() -> None:
    from click import unstyle
    from typer.testing import CliRunner

    from ops_composer.cli import app as cli_app

    command = CliRunner()
    result = command.invoke(cli_app, ["--help"])
    output = unstyle(result.stdout)
    assert result.exit_code == 0
    assert "admin" in output
    assert "worker" in output
    assert "migrate" in output
    assert "purge-expired-auth" in output

    bootstrap = command.invoke(cli_app, ["admin", "bootstrap", "--help"])
    assert bootstrap.exit_code == 0
    assert "--username" in unstyle(bootstrap.stdout)
    assert "--password" not in unstyle(bootstrap.stdout)
