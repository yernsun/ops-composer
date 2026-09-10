# Contributing to OpsComposer

[简体中文](CONTRIBUTING.zh-CN.md) | English

Bug reports, design discussion, testing results, and narrowly scoped proposals are welcome. Read
[AGENTS.md](AGENTS.md), the relevant rules in `docs/agent-rules/`, and
[SECURITY.md](SECURITY.md) before submitting material.

## Current contribution gate

The contributor license agreement (CLA) is **not active yet** because the receiving legal party,
final agreement, privacy notice, and acceptance-record system have not been published. To preserve
a verifiable rights chain for a possible future dual-license offering, maintainers must not merge
code, documentation, artwork, translations, or other copyrightable material from an external
contributor until that contributor has accepted the then-current CLA.

External contributors may still:

- open issues and participate in design discussions;
- provide reproduction steps, test results, and factual interoperability information; and
- propose a change for a maintainer to implement independently.

Do not paste a proposed patch into an issue to bypass the CLA gate. A pull request may be opened for
review, but it cannot be merged before the gate is active and satisfied. Closing or declining a
contribution does not restrict the contributor's rights in their own material.

See [CLA_POLICY.md](CLA_POLICY.md) for the activation requirements. A `Signed-off-by` line or the
Developer Certificate of Origin does not replace the project CLA because neither, by itself,
grants the project steward the relicensing rights required for a proprietary alternative.

## Contribution requirements after CLA activation

When the repository announces an active CLA process, every contributor must:

1. accept the exact published CLA version through the documented identity and record process;
2. have authority from any employer or other owner that may control the contribution;
3. submit original or authorized material and disclose every third-party source and restriction;
4. avoid secrets, personal data, customer data, and confidential information;
5. add or preserve SPDX/license notices for dependency, vendored, generated, and copied material;
6. update both supported locales for user-visible text; and
7. run `python3 harness/check.py` and report any skipped infrastructure checks.

Contributions are voluntary and do not create employment, payment, support, roadmap, or acceptance
obligations. GitHub Sponsors or PayPal funding does not influence technical acceptance.

## Maintainer rights records

Maintainers must also document who owns each contribution and any employer clearance. Before any
commercial license is offered, the project must audit pre-CLA history and obtain any missing
licenses or assignments. A CLA cannot retroactively cure an unknown earlier contribution.
