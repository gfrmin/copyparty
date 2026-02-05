#!/usr/bin/env python3
"""
Analyze bare except blocks and suggest specific exception types.

Usage:
    python3 scripts/fix-bare-excepts.py              # analyze all files
    python3 scripts/fix-bare-excepts.py copyparty/   # analyze specific directory
    python3 scripts/fix-bare-excepts.py copyparty/util.py  # analyze specific file
"""

import ast
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class BareExceptAnalyzer(ast.NodeVisitor):
    """Analyze bare except blocks and categorize them."""

    def __init__(self, filename: str):
        self.filename = filename
        self.bare_excepts: List[Dict] = []
        self.current_func = None
        self.current_class = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old_func = self.current_func
        self.current_func = node.name
        self.generic_visit(node)
        self.current_func = old_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        old_func = self.current_func
        self.current_func = node.name
        self.generic_visit(node)
        self.current_func = old_func

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_Try(self, node: ast.Try) -> None:
        for handler in node.handlers:
            if handler.type is None:  # bare except
                category = self._infer_category(handler, node)
                suggestion = self._suggest_exception(handler, node)

                self.bare_excepts.append({
                    'lineno': node.lineno,
                    'handler_lineno': handler.lineno,
                    'function': self.current_func,
                    'class': self.current_class,
                    'category': category,
                    'suggestion': suggestion,
                    'handler_body_size': len(handler.body),
                })
        self.generic_visit(node)

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
            elif isinstance(node, ast.Attribute):
                if isinstance(node.ctx, ast.Del):
                    patterns.append("DelAttr")
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('pop', 'get', 'setdefault'):
                        patterns.append(node.func.attr)

        if 'pop' in patterns or 'Subscript' in patterns:
            return True, "(KeyError, IndexError, ValueError)"
        elif 'get' in patterns or 'setdefault' in patterns:
            return True, "KeyError"
        return False, ""

    def _is_parsing_error_pattern(self, node: ast.Try) -> bool:
        """Check if try block contains parsing/network operations."""
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Call):
                if isinstance(stmt.func, ast.Attribute):
                    attr = stmt.func.attr
                    if attr in ('split', 'strip', 'parse', 'unpack', 'decode', 'encode',
                                'int', 'float', 'json.loads', 'json.dumps',
                                'socket', 'sendall', 'recv', 'connect'):
                        return True
        return False

    def _is_pass_pattern(self, handler: ast.ExceptHandler) -> bool:
        """Check if handler just passes."""
        return len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass)

    def _is_logging_pattern(self, handler: ast.ExceptHandler) -> bool:
        """Check if handler just logs and continues."""
        for node in ast.walk(handler):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('error', 'warning', 'info', 'debug', 'exception', 'log'):
                        return True
        return False

    def _infer_category(self, handler: ast.ExceptHandler, node: ast.Try) -> str:
        """Infer category of bare except block."""

        # Import fallback
        if self._is_import_context(node):
            return "import_fallback"

        # Dict/list access
        is_dict_pattern, _ = self._is_dict_access_pattern(handler)
        if is_dict_pattern:
            return "dict_list_access"

        # Parsing/network
        if self._is_parsing_error_pattern(node):
            return "parsing_network"

        # Silent pass
        if self._is_pass_pattern(handler):
            return "silent_pass"

        # Just logging
        if self._is_logging_pattern(handler):
            return "logging_only"

        return "unknown"

    def _suggest_exception(self, handler: ast.ExceptHandler, node: ast.Try) -> str:
        """Suggest specific exception type."""
        category = self._infer_category(handler, node)

        if category == "import_fallback":
            return "ImportError"
        elif category == "dict_list_access":
            _, exc_type = self._is_dict_access_pattern(handler)
            return exc_type
        elif category == "parsing_network":
            return "(ValueError, TypeError, UnicodeDecodeError, IndexError)"
        elif category == "silent_pass":
            return "Exception  # TODO: review and narrow"
        elif category == "logging_only":
            return "Exception  # TODO: review and narrow"
        else:
            return "Exception  # TODO: review and narrow"


def analyze_file(filepath: str) -> List[Dict]:
    """Analyze a single Python file for bare excepts."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        tree = ast.parse(content, filename=filepath)
        analyzer = BareExceptAnalyzer(filepath)
        analyzer.visit(tree)
        return analyzer.bare_excepts
    except (SyntaxError, UnicodeDecodeError) as e:
        print(f"Error parsing {filepath}: {e}", file=sys.stderr)
        return []


def analyze_directory(dirpath: str) -> Tuple[List[Dict], Dict[str, int]]:
    """Analyze all Python files in a directory."""
    all_excepts = []
    category_counts = defaultdict(int)

    for filepath in Path(dirpath).rglob('*.py'):
        # Skip test files and vendored code for now
        if '__pycache__' in str(filepath):
            continue
        if 'stolen' in str(filepath):
            continue

        excepts = analyze_file(str(filepath))
        for exc in excepts:
            exc['file'] = str(filepath)
            all_excepts.append(exc)
            category_counts[exc['category']] += 1

    return all_excepts, dict(category_counts)


def print_summary(excepts: List[Dict], category_counts: Dict[str, int]) -> None:
    """Print summary report."""
    print("\n" + "="*80)
    print("BARE EXCEPT BLOCK ANALYSIS REPORT")
    print("="*80 + "\n")

    total = len(excepts)
    print(f"Total bare except blocks: {total}\n")

    print("CATEGORY BREAKDOWN:")
    print("-" * 80)
    for category in sorted(category_counts.keys()):
        count = category_counts[category]
        pct = (count / total * 100) if total > 0 else 0
        print(f"  {category:20s}: {count:4d} ({pct:5.1f}%)")
    print()

    # Group by category and file
    by_category: Dict[str, List[Dict]] = defaultdict(list)
    for exc in excepts:
        by_category[exc['category']].append(exc)

    print("\nDETAILED BREAKDOWN BY CATEGORY:")
    print("=" * 80)

    for category in sorted(by_category.keys()):
        items = by_category[category]
        print(f"\n{category.upper()} ({len(items)} items)")
        print("-" * 80)

        by_file: Dict[str, List[Dict]] = defaultdict(list)
        for item in items:
            by_file[item['file']].append(item)

        for filepath in sorted(by_file.keys()):
            file_items = by_file[filepath]
            print(f"\n  {filepath}  ({len(file_items)} blocks)")

            for item in sorted(file_items, key=lambda x: x['lineno']):
                func_info = f"{item['class']}." if item['class'] else ""
                func_info += item['function'] if item['function'] else "<module>"

                print(f"    Line {item['lineno']:5d}: {func_info}")
                print(f"               → Suggestion: except {item['suggestion']}")


def print_csv(excepts: List[Dict]) -> None:
    """Print CSV format for further processing."""
    print("file,lineno,function,category,suggestion")
    for exc in sorted(excepts, key=lambda x: (x['file'], x['lineno'])):
        func = exc.get('function') or '<module>'
        print(f"{exc['file']},{exc['lineno']},{func},{exc['category']},{exc['suggestion']}")


def main() -> None:
    """Main entry point."""
    target = sys.argv[1] if len(sys.argv) > 1 else "copyparty"
    csv_output = "--csv" in sys.argv

    if os.path.isfile(target):
        excepts = analyze_file(target)
        category_counts = defaultdict(int)
        for exc in excepts:
            category_counts[exc['category']] += 1
    else:
        excepts, category_counts = analyze_directory(target)

    if csv_output:
        print_csv(excepts)
    else:
        print_summary(excepts, category_counts)

        # Additional stats
        print("\nFIXING PRIORITY (recommended order):")
        print("-" * 80)
        print("1. import_fallback (safest)          - Replace with: except ImportError:")
        print("2. dict_list_access (mechanical)    - Replace with: except (KeyError, IndexError):")
        print("3. parsing_network (requires care)  - Analyze per case")
        print("4. logging_only (review needed)     - Decide per case")
        print("5. silent_pass (review needed)      - Decide per case")
        print("6. unknown (manual review)          - Decide per case")


if __name__ == '__main__':
    main()
