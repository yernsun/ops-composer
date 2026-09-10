# Third-party notices

This file is a human-readable notice index for the dependency locks dated 2026-09-10. It does not
replace the license text shipped by an upstream package. The project license in [LICENSE](LICENSE)
covers only material offered by the relevant OpsComposer copyright holders; third-party material
remains under its own terms.

The authoritative resolved sets are `backend/uv.lock` and `frontend/package-lock.json`. A release
must retain the license and notice files from **every** resolved component actually included in
that release, including transitive, native, image-base, and operating-system components. See
[docs/legal/dependency-compliance.md](docs/legal/dependency-compliance.md) before distribution.

## Project Forge material

OpsComposer was generated from Project Forge commit
[`a36fb96da3780b4bb8086cbbdb803e08ec163457`](https://github.com/yernsun/project-forge/commit/a36fb96da3780b4bb8086cbbdb803e08ec163457),
which is licensed under the MIT License. Its license is preserved at
`third_party/project-forge/LICENSE`. That verbatim file, including the copyright and permission
notice, must accompany copies or substantial portions of the Project Forge material.

## Direct backend runtime dependencies

| Component | Resolved version | Reported or observed license |
|---|---:|---|
| ansible-core | 2.19.12 | GPL-3.0-or-later, with separately licensed bundled material |
| ansible-runner | 2.4.3 | Package metadata: Apache-2.0; bundled `awx_display.py`: GPL-3.0-or-later notice |
| argon2-cffi | 25.1.0 | MIT |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause |
| FastAPI | 0.141.1 | MIT |
| psycopg, psycopg-binary, psycopg-pool | 3.3.4 / 3.3.4 / 3.3.1 | LGPL-3.0-only |
| Pydantic | 2.13.4 | MIT |
| pydantic-settings | 2.15.0 | MIT |
| PyYAML | 6.0.3 | MIT |
| Typer | 0.27.1 | MIT |
| certifi (transitive runtime dependency) | 2026.7.22 | MPL-2.0 |

The installed Python distributions retain their upstream license files under their `.dist-info`
directories. `ansible-runner` is not safely summarized as Apache-only: OpsComposer's normal Runner
path loads its GPL-noticed `awx_display.py`. Treat the Ansible execution stack as a mixed-license,
copyleft boundary.

The OpsComposer wheel declares `License-Expression: AGPL-3.0-only` and includes the canonical AGPL
text, `NOTICE.md`, and the inherited Project Forge MIT license under its `.dist-info/licenses/`
directory. Dependency wheels remain responsible for carrying their own upstream notices.

## Direct frontend runtime dependencies

The following resolved direct dependencies report MIT licensing in the current npm lock:

| Component | Resolved version | License |
|---|---:|---|
| @primeuix/themes | 1.2.5 | MIT |
| @tanstack/vue-query | 5.101.4 | MIT |
| @xterm/addon-fit | 0.11.0 | MIT |
| @xterm/xterm | 6.0.0 | MIT |
| openapi-fetch | 0.14.1 | MIT |
| Pinia | 3.0.4 | MIT |
| PrimeIcons | 7.0.0 | MIT |
| PrimeVue | 4.5.5 | MIT |
| Vue | 3.5.41 | MIT |
| vue-i18n | 11.4.8 | MIT |
| Vue Router | 4.6.4 | MIT |

No PrimeVue premium template or commercial Theme Designer asset was identified in the lock or
source audit. Such assets are not covered by PrimeVue core's MIT license and must not be added
without separately recording their terms.

`frontend/scripts/generate-license-bundle.mjs` copies the full license/notice files for the locked
non-development npm packages into `dist/legal/npm/` during a production build. It also publishes
the OpsComposer license/policies, compliance notes, and preserved upstream license files under
`dist/legal/` so the application server can expose them without a separate artifact.

## Container and build-tool material

The release image additionally contains or derives from Node.js 24 Bookworm Slim build image
`sha256:2fe369e969550cde8e867afc3fe370b260140cab4a23d467074295b42163d553`, Python 3.13
Alpine 3.23 runtime image
`sha256:75f27d686432419c9d42420b2b9ef605868c7a0682a6be10a6601fad46c2df01`, Alpine packages,
OpenSSH, sshpass, tini, libuuid (from util-linux), CA certificates, and uv 0.12.5 image
`sha256:e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1`. Their upstream
terms remain applicable. uv 0.12.5 is offered under Apache-2.0 OR MIT; copies are preserved in
`third_party/uv/`. Alpine's installed-package database and Python `.dist-info` licenses must remain
in any distributed image. See [CONTAINER.md](CONTAINER.md) for the image evidence and corresponding
source process.

This notice does not grant trademark rights and is not legal advice.
