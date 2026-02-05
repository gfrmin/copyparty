#!/usr/bin/env python3
"""
Automatically fix bare except blocks based on category.

Usage:
    python3 scripts/apply-fixes.py import_fallback      # Fix all import fallbacks
    python3 scripts/apply-fixes.py dict_list_access     # Fix dict/list accesses
    python3 scripts/apply-fixes.py --dry-run import_fallback  # Preview changes
"""

import ast
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class BareExceptFixer(ast.NodeTransformer):
    """Fix bare except blocks with specific exception types."""

    def __init__(self, filename: str, category: str, dry_run: bool = False):
        self.filename = filename
        self.category = category
        self.dry_run = dry_run
        self.fixed_count = 0
        self.changes: List[Tuple[int, str, str]] = []

    def visit_Try(self, node: ast.Try) -> ast.Try:
        for handler in node.handlers:
            if handler.type is None:  # bare except
                exc_type = self._get_exception_type(handler, node)
                if exc_type:
                    # Create new handler with specific exception type
                    if ',' in exc_type:
                        # Multiple exceptions: except (ValueError, KeyError):
                        parts = [p.strip() for p in exc_type.split(',')]
                        handler.type = ast.Tuple(
                            elts=[ast.Name(id=p.strip(), ctx=ast.Load()) for p in parts],
                            ctx=ast.Load()
                        )
                    else:
                        # Single exception: except ImportError:
                        handler.type = ast.Name(id=exc_type.strip(), ctx=ast.Load())

                    self.fixed_count += 1
                    self.changes.append((node.lineno, f"except {exc_type}:", handler))

        self.generic_visit(node)
        return node

    def _get_exception_type(self, handler: ast.ExceptHandler, node: ast.Try) -> Optional[str]:
        """Get exception type based on category."""
        if self.category == "import_fallback":
            if self._is_import_context(node):
                return "ImportError"
        elif self.category == "dict_list_access":
            if self._is_dict_access_pattern(handler)[0]:
                return self._is_dict_access_pattern(handler)[1]
        return None

    def _is_import_context(self, node: ast.Try) -> bool:
        """Check if try block contains imports."""
        for stmt in node.body:
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                return True
        return False

    def _is_dict_access_pattern(self, handler: ast.ExceptHandler) -> Tuple[bool, str]:
        """Detect dictionary/list access error patterns."""
        patterns = []
        for node in ast.walk(handler):
            if isinstance(node, ast.Subscript):
                patterns.append("Subscript")
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('pop', 'get', 'setdefault'):
                        patterns.append(node.func.attr)

        if 'pop' in patterns or 'Subscript' in patterns:
            return True, "(KeyError, IndexError, ValueError)"
        elif 'get' in patterns or 'setdefault' in patterns:
            return True, "KeyError"
        return False, ""


def read_file(filepath: str) -> str:
    """Read file contents."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()


def write_file(filepath: str, content: str) -> None:
    """Write file contents."""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)


def fix_file(filepath: str, category: str, dry_run: bool = False) -> int:
    """Fix bare excepts in a single file."""
    try:
        content = read_file(filepath)
        tree = ast.parse(content, filename=filepath)
        fixer = BareExceptFixer(filepath, category, dry_run)
        new_tree = fixer.visit(tree)

        if fixer.fixed_count > 0:
            if dry_run:
                print(f"\n{filepath}: {fixer.fixed_count} fixes")
                for lineno, exc_type, _ in fixer.changes:
                    print(f"  Line {lineno}: {exc_type}")
            else:
                new_content = ast.unparse(new_tree)
                write_file(filepath, new_content)
                print(f"Fixed {filepath}: {fixer.fixed_count} blocks")

        return fixer.fixed_count

    except (SyntaxError, UnicodeDecodeError) as e:
        print(f"Error processing {filepath}: {e}", file=sys.stderr)
        return 0


def main() -> None:
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/apply-fixes.py <category> [--dry-run]")
        sys.exit(1)

    category = sys.argv[1]
    dry_run = "--dry-run" in sys.argv

    valid_categories = ["import_fallback", "dict_list_access", "parsing_network"]
    if category not in valid_categories:
        print(f"Invalid category: {category}")
        print(f"Valid categories: {', '.join(valid_categories)}")
        sys.exit(1)

    # Find all Python files
    copyparty_dir = Path("copyparty")
    if not copyparty_dir.exists():
        print("Error: copyparty directory not found")
        sys.exit(1)

    total_fixed = 0
    mode = "DRY RUN" if dry_run else "FIXING"
    print(f"\n{mode}: {category}\n" + "=" * 60)

    for filepath in sorted(copyparty_dir.rglob("*.py")):
        if "__pycache__" in str(filepath):
            continue
        total_fixed += fix_file(str(filepath), category, dry_run)

    print("\n" + "=" * 60)
    print(f"Total fixed: {total_fixed}")


if __name__ == "__main__":
    main()
