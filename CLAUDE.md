# CLAUDE.md — copyparty

## AI/LLM Policy

This is a fork. AI-assisted code contributions are welcome.

---

## Build Commands

```bash
# Build the self-extracting archive (main distributable)
./scripts/make-sfx.sh           # regular build
./scripts/make-sfx.sh fast      # faster build, worse js/css compression
./scripts/make-sfx.sh gz fast   # gzip-compressed, fast

# Compress web assets (requires pigz/zopfli)
make -C copyparty/web

# Build for PyPI
./scripts/make-pypi-release.sh d   # dry run
./scripts/make-pypi-release.sh t   # test upload
./scripts/make-pypi-release.sh u   # real upload

# Install in dev mode
pip install -e .
```

## Test Commands

```bash
# Run all tests (unit tests + smoketest)
./scripts/run-tests.sh

# Run only with a specific Python version
./scripts/run-tests.sh python3

# Run unit tests directly
python3 -m unittest discover -s tests

# Run a single test file
python3 -m unittest tests.test_authctx

# Run a specific test class
python3 -m unittest tests.test_authctx.TestAuthCtx

# Run a specific test method
python3 -m unittest tests.test_authctx.TestAuthCtx.test_resolve_credentials

# Run smoketest directly
python3 scripts/test/smoketest.py
```

Tests use Python's built-in `unittest` framework (not pytest). Test files are in `tests/`.

**Test utilities** (`tests/util.py`):
- `Cfg`: `Namespace` wrapper for building test args with sensible defaults
- `get_ramdisk()`: Cross-platform ramdisk allocation (`/dev/shm`, `/Volumes/cptd`, or tempdir fallback)
- `VHttpConn`, `VHttpSrv`: Virtual HTTP connection/server for testing without actual sockets

## Lint & Format

```bash
ruff check copyparty/          # linter (line-length=120)
black copyparty/                # formatter (target: py39)
isort copyparty/                # import sorting (black profile)
pylint copyparty/               # static analysis
mypy copyparty/                 # type checking (strict mode)
bandit -r copyparty/            # security linting
eslint copyparty/web/**/*.js    # javascript linting
```

Key lint config (from `pyproject.toml`):
- Line length: **120**
- Line endings: **LF**
- Ruff ignores: E402 (import order), E722 (bare except)
- Black target: py39

## Dev Environment Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install jinja2                                                   # mandatory
pip install argon2-cffi pyzmq mutagen paramiko pyftpdlib partftpy    # optional features
pip install Pillow pillow-heif pyvips                                # thumbnails
pip install black bandit pylint flake8 isort mypy                        # dev tools
```

## Architecture Overview

copyparty is a portable file server supporting HTTP(S), WebDAV, SFTP, FTP(S), TFTP, and SMB/CIFS. It requires only Python 3.9+; all other dependencies are optional.

### Directory Structure

```
copyparty/           Main Python package
  __main__.py        Entry point and CLI (~162 KB)
  httpcli.py         HTTP request handling (~266 KB)
  authsrv.py         Authentication and authorization (~146 KB)
  up2k.py            Upload protocol + file indexing + DB management (~192 KB)
  svchub.py          Service hub, coordinates subsystems (~59 KB)
  util.py            Shared utilities (~122 KB)
  sftpd.py           SFTP server (paramiko)
  ftpd.py            FTP/FTPS server (pyftpdlib)
  tftpd.py           TFTP server (partftpy)
  smbd.py            SMB/CIFS server (impacket)
  api.py             API dispatch router (.cpr/api/*)
  authctx.py         Auth middleware (pure functions)
  db/                DB repositories (SQLite, repository pattern)
  mtag.py            Metadata tagging / media indexer
  u2idx.py           up2k file indexing
  web/               Frontend (vanilla JS, no build step)
    browser.js       Main UI (~263 KB)
    up2k.js          Upload client (~108 KB)
    util.js          JS utilities (~59 KB)
    browser.css      Main stylesheet (~77 KB)
    tl/              Translations (21 languages)
    deps/            Frontend dependencies (pre-minified/compressed)
    a/               Standalone web apps (u2c, partyfuse)
  stolen/            Vendored dependencies (dnslib, ifaddr, qrcodegen)
  res/               Resources (license, TLS fallback cert)

scripts/             Build, release, and test scripts
bin/                 Utility scripts, hooks, mtag plugins
tests/               Unit tests (unittest)
contrib/             Third-party integrations (nginx, systemd, docker, themes)
docs/                Documentation
```

### Layered Architecture (Feb 2025)

Commit `eae43d05` introduced architectural decoupling:

- **API Layer** (`api.py`): Dispatch router for `.cpr/api/*` endpoints with standardized JSON responses (`{"ok": bool, "data": ..., "error": ...}`)
- **Auth Middleware** (`authctx.py`): Pure functions for credential resolution, IP user mapping, and permission resolution
- **DB Repositories** (`db/`): Repository pattern for SQLite operations
  - `FileRepository` (`file_repo.py`): Upload tracking (up, mt, kv, dh, iu, cv, ds tables)
  - `SessionRepository`, `ShareRepository` (actively used), `IdpRepository`

**ShareRepository activation**: As of Feb 2025, `ShareRepository` is actively used in `httpcli.py` for all share operations (listing, creating, deleting, updating expiry). The repository is accessed via `U2idx.get_share_repo()` in `u2idx.py`. This replaced ~15 direct SQL queries with repository method calls.

### Key Concepts

- **up2k protocol**: Resumable chunked uploads with per-chunk SHA-512 hashing, deduplication, and integrity verification. Files are split into chunks (1 MiB default, up to 32 MiB), hashed client-side, and reassembled server-side.
- **SFX build**: The main distributable is a self-extracting Python archive (`copyparty-sfx.py`) that bundles everything into a single file.
- **Database**: SQLite for upload tracking, file metadata, and search indexes.
- **Pebkac exception** (`util.py:4469`): Client error class carrying an HTTP status code. API handlers raise `Pebkac` for 4xx errors; generic `Exception` maps to 500.
- **Permissions**: `resolve_permissions()` in `authctx.py` returns a 9-tuple: `(read, write, move, delete, get, upget, html, admin, dot)`. Special users: `"*"` (anonymous), `"leeloo_dallas"` (internal operations).
- **Main branch**: This fork uses `master`. Upstream (9001/copyparty) uses `hovudstraum`.

### Entry Points

- `copyparty` -> `copyparty.__main__:main`
- `u2c` -> `copyparty.web.a.u2c:main` (upload client)
- `partyfuse` -> `copyparty.web.a.partyfuse:main` (FUSE mount)

## Code Conventions

- Python 3.9+ required. Type hints are used throughout.
- Large files are common; several core modules exceed 100 KB. The codebase is "organic" — features were added incrementally.
- Frontend is vanilla JavaScript with no transpilation/bundling. Web assets are gzip-compressed (via `pigz`/`zopfli`) but have no webpack/babel/node.js build step.
- Only required runtime dependency is `jinja2`; everything else is optional.
- MIT licensed.
