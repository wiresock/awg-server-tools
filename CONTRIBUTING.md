# Contributing

Thank you for your interest in AmneziaWG Server Tools. Bug reports, fixes and
improvements are welcome as GitHub issues and pull requests.

Component-specific build and test instructions are in
[`amneziawg-web/CONTRIBUTING.md`](amneziawg-web/CONTRIBUTING.md) for the web
panel and in the documentation of each component. Keep each pull request to
one concern, keep the existing tests passing and add tests for new behaviour.

## Licensing of contributions

This project is distributed under the MIT License (see [`LICENSE`](LICENSE)
and [`NOTICE.md`](NOTICE.md)). By submitting a contribution you agree that:

- it is licensed under the license of the files it changes or adds, which for
  everything this project maintains is the MIT License, as stated in each
  file's `SPDX-License-Identifier` or in [`REUSE.toml`](REUSE.toml);
- you have the right to submit it under that license: you wrote it, or it is
  otherwise available to you under terms compatible with the MIT License, and
  your employer or anyone else with rights in it has allowed you to contribute
  it.

You keep the copyright in your contribution. There is no copyright assignment
and no Contributor License Agreement. Contributions are accepted only under the
terms above; they do not grant the maintainer any additional right, such as a
right to relicense them under other terms.

### The maintainer and other contributors

The project is maintained by Vadim Smirnov, who does business as WireSock.
WireSock is a trade name, not a separate legal entity, and holds no rights of
its own. Notices that read `Vadim Smirnov (doing business as WireSock)` refer to
his own work. Accepting your contribution into the repository does not make it
his: the notices for his work do not cover it, and your contribution stays
yours, licensed under MIT.

Do not submit code, text or images copied from elsewhere unless their license
allows it and you say where they come from in the pull request. Code under a
license other than MIT (for example GPL, LGPL, MPL or a license with no
permission to redistribute) cannot be accepted into the repository's MIT
components.

### Signing off (optional)

You may add a `Signed-off-by:` line to your commits (`git commit -s`) to
certify the [Developer Certificate of Origin](https://developercertificate.org/).
It is welcome but not required, and it does not change the licensing terms
above.

### Copyright and license headers

The repository follows the [REUSE](https://reuse.software) specification, and
CI runs `reuse lint`.

- When you add a new file, start it with your own copyright line and the
  license of its neighbours. For a Rust file:

  <!-- REUSE-IgnoreStart -->
  ```rust
  // SPDX-FileCopyrightText: <year> <your name>
  // SPDX-License-Identifier: MIT
  ```
  <!-- REUSE-IgnoreEnd -->

  Do not copy the maintainer's copyright line onto your own work.
- When you contribute a substantial part of an existing file, you may add your
  own `SPDX-FileCopyrightText` line to it, below the existing ones.
- The globs in `REUSE.toml` attribute files without an inline header to the
  maintainer. If you add such a file, give it your own header, which takes
  precedence. Where a header would change the file or cannot be added (HTML
  and CSS templates, sqlx migrations, JSON or hex fixtures, images), add a
  `<file>.license` file next to it with the two SPDX lines instead, or ask for
  an entry in `REUSE.toml` in your pull request.
- Never remove or change someone else's copyright line.

`bash scripts/check-licensing.sh` runs all licensing checks locally; it needs
`reuse` and `cargo-deny` (see [`docs/LICENSING.md`](docs/LICENSING.md#automated-checks)).

## Reporting security issues

Please do not open public issues for security vulnerabilities. Contact the
maintainers through the contact methods on the repository.
