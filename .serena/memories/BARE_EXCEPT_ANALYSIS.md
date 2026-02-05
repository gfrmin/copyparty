# Bare Except Block Analysis - Copyparty Technical Debt

## Summary
- **Total bare excepts found**: 545 (across 41 Python files)
- **Analysis tool**: `/scripts/fix-bare-excepts.py` - categorizes bare excepts automatically

## Category Breakdown

| Category | Count | % | Difficulty |
|----------|-------|---|------------|
| import_fallback | 41 | 7.5% | Low (safest) |
| dict_list_access | 44 | 8.1% | Low (mechanical) |
| parsing_network | 79 | 14.5% | Medium |
| logging_only | 44 | 8.1% | Medium |
| silent_pass | 150 | 27.5% | High |
| unknown | 187 | 34.3% | High |

## Recommended Fixing Order

1. **import_fallback (41)** → `except ImportError:`
   - Files: util.py (15), __main__.py (2), svchub.py (5), th_srv.py (3), web/a/ (3+)
   - Risk: Very low, safe isolated fixes

2. **dict_list_access (44)** → `except (KeyError, IndexError):`
   - Files: authsrv.py (8), up2k.py (6), httpcli.py (4), util.py (9)
   - Risk: Low, pattern-based replacements

3. **parsing_network (79)** → `except (ValueError, TypeError, UnicodeDecodeError, IndexError):`
   - Files: httpcli.py (18), util.py (19), authsrv.py (10)
   - Risk: Medium, context-dependent

4. **logging_only + silent_pass (194)** → Requires case-by-case review
   - Risk: High, need human judgment

5. **unknown (187)** → Manual review required

## High-Value Files
- **copyparty/util.py** (80 bare excepts) - god module, multiple categories
- **copyparty/httpcli.py** (41 bare excepts) - HTTP handling
- **copyparty/up2k.py** (43 bare excepts) - Upload protocol
- **copyparty/authsrv.py** (33 bare excepts) - Auth system
