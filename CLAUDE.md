# CLAUDE.md — copyparty

## IMPORTANT: AI/LLM Policy

**The CONTRIBUTING.md explicitly states: "do not use AI / LLM when writing code."**
copyparty is "100% organic, free-range, human-written software." Any code contributions must be entirely human-written. The only exception is translations, and only if verified by a fluent speaker.

Keep this in mind: do not generate code intended for contribution upstream.

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
# Run all tests (unit tests + smoketest, both Python 2 and 3)
./scripts/run-tests.sh

# Run only with a specific Python version
./scripts/run-tests.sh python3
./scripts/run-tests.sh python2

# Run unit tests directly
python3 -m unittest discover -s tests

# Run smoketest directly
python3 scripts/test/smoketest.py
```

Tests use Python's built-in `unittest` framework (not pytest). Test files are in `tests/`.

## Lint & Format

```bash
ruff check copyparty/          # linter (line-length=120)
black copyparty/                # formatter (target: py27, requires black==21.12b0)
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
- Black target: py27 (Python 2.7 compatible formatting)

## Dev Environment Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install jinja2 strip_hints                                       # mandatory
pip install argon2-cffi pyzmq mutagen paramiko pyftpdlib partftpy    # optional features
pip install Pillow pillow-heif pyvips                                # thumbnails
pip install black==21.12b0 click==8.0.2 bandit pylint flake8 isort mypy  # dev tools
```

## Architecture Overview

copyparty is a portable file server supporting HTTP(S), WebDAV, SFTP, FTP(S), TFTP, and SMB/CIFS. It requires only Python (2.7 or 3.3+); all other dependencies are optional.

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

### Key Concepts

- **up2k protocol**: Resumable chunked uploads with per-chunk SHA-512 hashing, deduplication, and integrity verification. Files are split into chunks (1 MiB default, up to 32 MiB), hashed client-side, and reassembled server-side.
- **SFX build**: The main distributable is a self-extracting Python archive (`copyparty-sfx.py`) that bundles everything into a single file.
- **Database**: SQLite for upload tracking, file metadata, and search indexes.
- **Main branch**: `hovudstraum` (not `main` or `master`).

### Entry Points

- `copyparty` -> `copyparty.__main__:main`
- `u2c` -> `copyparty.web.a.u2c:main` (upload client)
- `partyfuse` -> `copyparty.web.a.partyfuse:main` (FUSE mount)

## Code Conventions

- Python 2.7 + 3.3+ compatibility: type hints exist in source but are stripped for PyPI releases (via `strip_hints`) to support older Python.
- Large files are common; several core modules exceed 100 KB. The codebase is "organic" — features were added incrementally.
- Frontend is vanilla JavaScript with no transpilation/bundling. Web assets are gzip-compressed (via `pigz`/`zopfli`) but have no webpack/babel/node.js build step.
- Only required runtime dependency is `jinja2`; everything else is optional.
- MIT licensed.
