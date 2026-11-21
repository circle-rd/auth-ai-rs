# Contributing to auth-ai (Rust)

> Welcome — this document covers contributor onboarding, versioning policy,
> releases and the Git workflow. **All technical standards** (typing,
> architecture, testing, error handling, security) live in
> [AGENTS.md](AGENTS.md) and are the canonical reference. Read both documents
> before opening a PR.

---

## 1. Development environment

### Prerequisites

- [rustup](https://rustup.rs): `rust-toolchain.toml` pins Rust 1.89.0 (the MSRV), with
  `clippy` and `rustfmt`; the CI also runs stable
- A C toolchain (`cc`) for `aws-lc-sys`

### First-time setup

```bash
cargo test --all-features   # unit, integration and doc tests, no network
```

The tests run against a scripted mock identity provider
(`tests/support/mod.rs`) plugged in through the `Transport` trait: no auth-service
instance is needed.

### Daily commands

For the full command table see [AGENTS.md → Build & Test Commands](AGENTS.md#build--test-commands).

| Command                                    | When to run                 |
| ------------------------------------------ | --------------------------- |
| `cargo test --all-features`                | While developing            |
| `cargo clippy --all-targets --all-features -- -D warnings` | Before committing |
| `cargo fmt --all`                          | To fix formatting           |
| `cargo doc --no-deps --all-features`       | Before opening a PR         |
| `cargo audit`                              | Before opening a PR         |

### Documentation

The documentation site lives in `docs-site/` (Docus). Build it in Docker:

```bash
docker build -t auth-ai-rs-docs ./docs-site
```

---

## 2. Versioning and breaking changes

This project follows **Semantic Versioning** (`MAJOR.MINOR.PATCH`). While the major
version is `0`, a breaking change bumps `MINOR`.

| Change type                      | Version bump | Required action        |
| -------------------------------- | ------------ | ---------------------- |
| Bug fix, no API change           | `PATCH`      | Changelog entry        |
| New feature, backward-compatible | `MINOR`      | Changelog entry + docs |
| Breaking change                  | `MAJOR`      | See below              |

### Breaking changes

A breaking change is anything that alters the public contract: a changed signature or
default, a removed export, a changed error code or response shape, a raised minimum
Rust or dependency version (the MSRV included).

**The rule: no backward-compatibility shims.** Bump the version, document the change
and a migration note in `CHANGELOG.md` and the docs, and remove the old behaviour.

The wire contract (BFF routes, cookie formats, error codes) is shared with the
TypeScript SDK `@circle-rd/auth-ai` and the Python SDK `auth-ai`: change it in all of
them, or not at all.

---

## 3. Releases

| Channel   | Trigger                                                 | crates.io version                                  |
| --------- | ------------------------------------------------------- | -------------------------------------------------- |
| nightly   | Manual run of the _Nightly_ workflow (`develop`/`main`) | `X.Y.Z-dev.YYYYMMDDHHMM` (pre-release, never picked by default) |
| stable    | A GitHub release `vX.Y.Z` created from `main`           | `X.Y.Z`                                           |

1. Merge `develop` into `main` through a pull request.
2. Set `version` in `Cargo.toml` (and refresh `Cargo.lock`), move the `[Unreleased]`
   entries of `CHANGELOG.md` under the new version, commit on `main`.
3. Create the GitHub release (and its tag `vX.Y.Z`) from `main`: this is the only
   trigger. The _Release_ workflow runs the quality gates, checks that the tag
   matches `Cargo.toml` and publishes. It never creates a release or a tag itself.
   A pre-release version (`X.Y.Z-rc.N`) needs a release marked _pre-release_.
4. Merge `main` back into `develop`.

If a release run fails, fix the cause, then delete the release **and** its tag and
create them again: re-running a job of a deleted tag fails at checkout. crates.io never
accepts the same version twice: bump it if a version was already uploaded.

A nightly is published as `X.Y.Z-dev.YYYYMMDDHHMM` without any commit (`X.Y.Z` is the
next patch when `Cargo.toml` holds an already published version). Nightlies stay on
crates.io: they can only be yanked, by a maintainer.

Both workflows currently publish with the `CARGO_REGISTRY_TOKEN` repository secret: a
trusted publisher is configured on an existing crate, so the very first version cannot use
OIDC. Once the first version of `auth-ai` is on crates.io, register `release.yml` and
`nightly.yml` of `circle-rd/auth-ai-rs` as trusted publishers (owner `circle-rd`, repository
`auth-ai-rs`, environment `crates-io`), re-enable the commented `crates-io-auth-action` steps
in both workflows, and remove the token from them.

---

## 4. Git workflow

### Branch naming

| Type          | Pattern                        | Example                    |
| ------------- | ------------------------------ | -------------------------- |
| Feature       | `feat/<short-description>`     | `feat/actix-adapter`       |
| Bug fix       | `fix/<short-description>`      | `fix/refresh-lock`         |
| Refactor      | `refactor/<short-description>` | `refactor/session-store`   |
| Chore / infra | `chore/<short-description>`    | `chore/update-deps`        |
| Breaking      | `breaking/<short-description>` | `breaking/handler-options` |

### Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

[optional body]

[optional footer: BREAKING CHANGE, Closes #issue]
```

Types: `feat`, `fix`, `refactor`, `test`, `chore`, `docs`, `perf`, `build`, `ci`.

### Pull request checklist

- [ ] `cargo fmt --all --check` and `cargo clippy --all-targets --all-features -- -D warnings` pass
- [ ] `cargo test --all-targets --all-features --locked` and `cargo test --doc --all-features` pass
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features` passes
- [ ] `cargo audit` reports nothing and `cargo package --locked` passes
- [ ] New behaviour has tests; a security check has a test that fails without it
- [ ] No `unwrap`, `expect`, `unsafe`, dead code, or secret or token in a message, log or test output
- [ ] Rustdoc, docs (`docs-site/`), README quick start and `CHANGELOG.md` updated for user-visible changes
- [ ] Breaking changes bump the version and carry a migration note

For the rationale behind each gate and the standards new code must meet, see
[AGENTS.md](AGENTS.md). Security vulnerabilities must **not** be reported in a public
issue: see [SECURITY.md](SECURITY.md).
