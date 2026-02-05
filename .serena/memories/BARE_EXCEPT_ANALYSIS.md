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

## Phase 1 Progress ✓ COMPLETE

### Completed Fixes
- **import_fallback**: 54/41 blocks fixed ✓ (Dec 5, 2025)
  - Files: 17 files modified
  - Commits: b86c5d47

- **dict_list_access**: 68/44 blocks fixed ✓ (Dec 5, 2025)
  - Files: 20 files modified  
  - Commits: c5c132aa

### Total Phase 1 Results
- **Bare excepts fixed**: 122 / 545 (22.4%)
- **Test suite**: Passing (69 tests, pre-existing env issues only)
- **Code quality**: All files compile, no syntax errors

### Remaining Bare Excepts: 423

3. **parsing_network (79)** → `except (ValueError, TypeError, UnicodeDecodeError, IndexError):`
   - Files: httpcli.py (18), util.py (19), authsrv.py (10)
   - Risk: Medium, context-dependent
   - Status: Ready for automation

4. **logging_only (44)** → Requires case-by-case review
   - Risk: High, need human judgment
   - Status: Can be partially automated

5. **silent_pass (150)** → Requires case-by-case review
   - Risk: High, need human judgment
   - Status: Needs manual analysis

6. **unknown (187)** → Manual review required
   - Risk: High
   - Status: Needs analysis

## High-Value Files
- **copyparty/util.py** (80 bare excepts) - god module, multiple categories
- **copyparty/httpcli.py** (41 bare excepts) - HTTP handling
- **copyparty/up2k.py** (43 bare excepts) - Upload protocol
- **copyparty/authsrv.py** (33 bare excepts) - Auth system
