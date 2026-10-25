# Contributing

Thank you for your interest in contributing to `amneziawg-web`.

---

## Getting started

```bash
git clone https://github.com/wiresock/awg-server-tools.git
cd awg-server-tools/amneziawg-web

# Build
cargo build

# Run tests
cargo test

# Lint
cargo clippy -- -D warnings
cargo fmt --check
```

All three checks must pass before a PR can be merged.

---

## Pull request guidelines

1. **One concern per PR.** Bug fixes, features, and refactors should be separate.
2. **Keep tests passing.** Add new tests when adding behaviour; do not delete existing tests.
3. **No sensitive data.** Do not commit passwords, tokens, private keys, or database files.
4. **Follow existing style.** The codebase uses `cargo fmt` (default settings) and passes `cargo clippy -- -D warnings`. Run both before opening a PR.
5. **Update docs.** If you change behaviour, update `README.md` and the relevant file in `docs/`.

---

## Reporting bugs

Open a GitHub issue with:

- What you expected to happen
- What actually happened
- Steps to reproduce
- Relevant log output (`RUST_LOG=amneziawg_web=debug`)
- Environment (OS, AWG version, Rust version)

Do **not** include passwords, tokens, or private keys in issues.

---

## Security issues

Please do not open public issues for security vulnerabilities.
Contact the maintainers directly via the repository contact methods.

---

## License

By contributing, you agree that your contributions will be licensed under the
MIT License, and that you have the right to submit them under it. You keep the
copyright in your contribution; there is no copyright assignment or CLA. See
the repository's [`CONTRIBUTING.md`](../CONTRIBUTING.md#licensing-of-contributions)
for the full terms and for the license headers new files need.
