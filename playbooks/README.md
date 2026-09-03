# Playbook workspace

Place reviewed `.yml` or `.yaml` playbooks under `playbooks/`. Production Compose mounts this
directory read-only at `/workspace`; OpsComposer rejects paths outside that boundary.
