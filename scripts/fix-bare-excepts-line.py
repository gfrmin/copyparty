#!/usr/bin/env python3
"""
Fix bare except blocks using line-based replacements to preserve formatting.

Usage:
    python3 scripts/fix-bare-excepts-line.py import_fallback [--dry-run]
    python3 scripts/fix-bare-excepts-line.py dict_list_access [--dry-run]
"""

import ast
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class BareExceptLocator(ast.NodeVisitor):
    """Find bare except blocks with line numbers."""

    def __init__(self, filename: str):
        self.filename = filename
        self.bare_excepts: List[Dict] = []

    def visit_Try(self, node: ast.Try) -> None:
        for handler in node.handlers:
            if handler.type is None:
                self.bare_excepts.append({
                    'lineno': handler.lineno,
                    'col_offset': handler.col_offset,
                })
        self.generic_visit(node)


def find_bare_excepts(filepath: str) -> List[int]:
    """Find all bare except handler line numbers in a file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        tree = ast.parse(content)
        locator = BareExceptLocator(filepath)
        locator.visit(tree)
        return sorted([exc['lineno'] for exc in locator.bare_excepts])
    except (SyntaxError, UnicodeDecodeError):
        return []


def read_lines(filepath: str) -> List[str]:
    """Read all lines from a file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.readlines()


def write_lines(filepath: str, lines: List[str]) -> None:
    """Write lines to a file."""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(lines)


def fix_import_fallback(lines: List[str], lineno: int) -> Optional[str]:
    """Fix bare except in import context."""
    idx = lineno - 1
    line = lines[idx]

    # Check if this is a bare except: block
    if not re.search(r'except\s*:\s*', line):
        return None

    # Check context: look backwards for import statement
    for i in range(max(0, idx - 10), idx):
        if re.search(r'(import|from\s+\S+\s+import)', lines[i]):
            # This is likely an import fallback
            new_line = re.sub(r'except\s*:', 'except ImportError:', line)
            return new_line

    return None


def fix_dict_list_access(lines: List[str], lineno: int) -> Optional[str]:
    """Fix bare except in dict/list access context."""
    idx = lineno - 1
    line = lines[idx]

    if not re.search(r'except\s*:\s*', line):
        return None

    # Check for dict/list operations in handler body
    indent = len(line) - len(line.lstrip())
    base_indent = indent + 4

    # Look ahead for .pop, .get, [..], etc.
    for i in range(idx + 1, min(len(lines), idx + 20)):
        current_line = lines[i]
        if current_line.strip() and len(current_line) - len(current_line.lstrip()) <= indent:
            # Left the except block
            break

        if re.search(r'\.(pop|get|setdefault)\s*\(', current_line):
            return re.sub(r'except\s*:', 'except KeyError:', line)
        elif re.search(r'\[.*\]', current_line):
            new_line = re.sub(r'except\s*:', 'except (KeyError, IndexError):', line)
            return new_line

    return None


def fix_parsing_network(lines: List[str], lineno: int) -> Optional[str]:
    """Fix bare except in parsing/network context."""
    idx = lineno - 1
    line = lines[idx]

    if not re.search(r'except\s*:\s*', line):
        return None

    # Check try block for parsing/network operations
    indent = len(line) - len(line.lstrip())

    # Look backwards for parsing/network patterns
    for i in range(max(0, idx - 25), idx):
        try_line = lines[i]

        # Parsing/conversion patterns
        if re.search(
            r'\.(split|strip|parse|decode|encode|int|float|loads|dumps)\s*\(',
            try_line
        ):
            new_line = re.sub(
                r'except\s*:',
                'except (ValueError, TypeError, UnicodeDecodeError, IndexError):',
                line
            )
            return new_line

        # JSON/unpacking patterns
        if re.search(r'json\.|unpack\(', try_line):
            new_line = re.sub(
                r'except\s*:',
                'except (ValueError, TypeError, UnicodeDecodeError, IndexError):',
                line
            )
            return new_line

        # Network/socket patterns
        if re.search(r'\.(socket|recv|send|connect|accept|listen)\s*\(', try_line):
            new_line = re.sub(
                r'except\s*:',
                'except (OSError, ValueError, TypeError, UnicodeDecodeError):',
                line
            )
            return new_line

    return None


def fix_except_block(lines: List[str], lineno: int, category: str) -> Optional[str]:
    """Fix a bare except block based on category."""
    if category == "import_fallback":
        return fix_import_fallback(lines, lineno)
    elif category == "dict_list_access":
        return fix_dict_list_access(lines, lineno)
    elif category == "parsing_network":
        return fix_parsing_network(lines, lineno)
    return None


def process_file(filepath: str, category: str, dry_run: bool = False) -> int:
    """Process a single file and fix bare excepts."""
    linenos = find_bare_excepts(filepath)
    if not linenos:
        return 0

    lines = read_lines(filepath)
    fixed_count = 0
    changes = []

    for lineno in linenos:
        new_line = fix_except_block(lines, lineno, category)
        if new_line is not None and new_line != lines[lineno - 1]:
            changes.append((lineno, lines[lineno - 1].rstrip(), new_line.rstrip()))
            if not dry_run:
                lines[lineno - 1] = new_line
            fixed_count += 1

    if changes:
        if dry_run:
            print(f"\n{filepath}:")
            for lineno, old, new in changes:
                print(f"  Line {lineno}:")
                print(f"    - {old}")
                print(f"    + {new}")
        else:
            write_lines(filepath, lines)
            print(f"✓ {filepath}: fixed {fixed_count} blocks")

    return fixed_count


def main() -> None:
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/fix-bare-excepts-line.py <category> [--dry-run]")
        sys.exit(1)

    category = sys.argv[1]
    dry_run = "--dry-run" in sys.argv

    valid_categories = ["import_fallback", "dict_list_access", "parsing_network"]
    if category not in valid_categories:
        print(f"Invalid category: {category}")
        print(f"Valid categories: {', '.join(valid_categories)}")
        sys.exit(1)

    copyparty_dir = Path("copyparty")
    if not copyparty_dir.exists():
        print("Error: copyparty directory not found")
        sys.exit(1)

    total_fixed = 0
    mode = "DRY RUN" if dry_run else "FIXING"
    print(f"\n{mode}: {category}\n" + "=" * 70)

    for filepath in sorted(copyparty_dir.rglob("*.py")):
        if "__pycache__" in str(filepath) or "stolen" in str(filepath):
            continue
        total_fixed += process_file(str(filepath), category, dry_run)

    print("\n" + "=" * 70)
    print(f"Total fixed: {total_fixed}\n")


if __name__ == "__main__":
    main()
