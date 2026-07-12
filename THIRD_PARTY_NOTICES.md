# Third-party notices

## Runtime dependency

- `typebox` 1.3.6, MIT license, https://github.com/sinclairzx81/typebox
- `nodemailer` 9.0.3, MIT-0 license, https://github.com/nodemailer/nodemailer
- `imapflow` 1.4.7, MIT license, https://github.com/postalsys/imapflow
- `mailparser` 3.9.14, MIT license, https://github.com/nodemailer/mailparser
- `html-to-text` 10.0.0, MIT license, https://github.com/html-to-text/node-html-to-text

The plugin imports OpenClaw's public plugin SDK at runtime from the host. OpenClaw 2026.6.11 is a development/test dependency and is not bundled into the RightOut release archive.

The complete production dependency closure contains the plugin root, five direct
runtime dependencies, and 41 transitive runtime packages. Exact versions,
integrity checksums, declared licenses, and package URLs are recorded in
`SBOM.spdx.json`. `npm-shrinkwrap.json` pins the same install graph; the release
gate regenerates the production SPDX component set and rejects drift.

## Research references

Official OpenClaw, EDPB, EUR-Lex, EDAA, Brave Search, broker/controller, government, legal, and commercial product pages are cited in the repository documentation and catalog. Facts and URLs are used as references; source prose, screenshots, proprietary reports, and broker datasets are not copied.

Hermes Unbroker at NousResearch/hermes-agent commit `2d9fd870b6d105e3b367aaa97477931b6671192e`, Privacy Guides, IntelTechniques, BADBOOL, and commercial privacy services informed gap categories only. RightOut ships no copied code, prose, templates, playbooks, or broker records from them. BADBOOL-derived material carries CC BY-NC-SA obligations and must not be imported without a separate license decision.
