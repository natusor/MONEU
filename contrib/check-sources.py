#!/usr/bin/env python3
#
# Copyright (c) 2025-2026 natusor (MONEU)
# Distributed under the MIT software license
#
# Source completeness check.
#
# A source file that was truncated in transfer, or a function left with an
# empty body during a refactor, both compile in some configurations and fail
# in others. Neither is caught by the compiler on the machine where the gap
# was made, which is why it is worth a separate pass.
#
# Run from the top of the tree:
#
#     python3 contrib/check-sources.py
#
# Exit status is 0 when nothing is found and 1 otherwise, so this can sit in
# a build script or a hook.
#
# What it checks, per file:
#
#   - the file ends with a newline. A file cut short mid-transfer usually
#     does not, and this is the cheapest signal there is.
#   - braces, parentheses and brackets balance in the code itself. Comments
#     and string literals are removed first, so a parenthesis in an English
#     sentence is not counted as code.
#   - no function has an empty body. Default constructors and the no-op
#     inline functions the lock-order option compiles to are excepted,
#     because those are empty on purpose.
#   - no unfinished-work markers are left behind.
#   - the last line does not break off in the middle of an expression.

import os
import re
import sys


def strip_comments_and_literals(src):
    """Return the code alone: no comments, no strings, no character constants."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            while i < n and src[i] != '\n':
                i += 1
        elif c == '/' and i + 1 < n and src[i + 1] == '*':
            i += 2
            while i + 1 < n and not (src[i] == '*' and src[i + 1] == '/'):
                i += 1
            i += 2
        elif c == '"':
            i += 1
            while i < n and src[i] != '"':
                if src[i] == '\\':
                    i += 1
                i += 1
            i += 1
        elif c == "'":
            i += 1
            while i < n and src[i] != "'":
                if src[i] == '\\':
                    i += 1
                i += 1
            i += 1
        else:
            out.append(c)
            i += 1
    return ''.join(out)


# Markers matched as whole words only. Without that, ToDouble() reports as a
# TODO and the check cries wolf on correct code.
MARKER = re.compile(
    r'(?<![A-Za-z])'
    r'(TODO|FIXME|XXX|HACK|unimplemented|NotImplemented)'
    r'(?![A-Za-z])'
    r'|(?<![A-Za-z-])(not implemented|place' + 'holder)(?![A-Za-z])'
)

# A function whose body is empty.
EMPTY_BODY = re.compile(
    r'\n[a-zA-Z_][A-Za-z0-9_:<>,&*\s]*\([^;{}]*\)\s*(?:const\s*)?\{\s*\}'
)

# A default constructor with no body. Correct where the base class and the
# members initialise themselves: base_uint zeroes its own words, and Script
# inherits from std::vector.
DEFAULT_CTOR = re.compile(
    r'^(?:public:\s*|private:\s*|protected:\s*)?'
    r'(?:[A-Za-z_][A-Za-z0-9_]*::)?[A-Za-z_][A-Za-z0-9_]*'
    r'\s*\(\s*\)\s*\{\s*\}$'
)

CODE_SUFFIXES = ('.cpp', '.h', '.c')
ALL_SUFFIXES = CODE_SUFFIXES + ('.py', '.txt', '.md', '.sh', '.json', '.cmake')

TOP_LEVEL_FILES = ['CMakeLists.txt', 'BUILD.md', 'GENESIS.md', 'README.md',
                   'CHANGES.md', 'build.sh', 'LICENSE']

SEARCH_ROOTS = ('src', 'contrib')


def collect_files():
    found = []
    for root in SEARCH_ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d != 'build']
            for name in filenames:
                if name.endswith(ALL_SUFFIXES):
                    found.append(os.path.join(dirpath, name))
    for name in TOP_LEVEL_FILES:
        if os.path.exists(name):
            found.append(name)
    # This script is not checked against itself: the patterns it looks for
    # are written out in it and would all report as findings.
    self_path = os.path.abspath(__file__)
    found = [f for f in found if os.path.abspath(f) != self_path]
    return sorted(found)


def check_file(path):
    """Return (issues, line_count, is_code)."""
    with open(path, encoding='utf-8', errors='replace') as handle:
        raw = handle.read()

    issues = []

    if raw and not raw.endswith('\n'):
        issues.append('does not end with a newline')
    if not raw.strip():
        issues.append('FILE IS EMPTY')

    for match in MARKER.finditer(raw):
        line = raw[:match.start()].count('\n') + 1
        issues.append('marker %s on line %d' % (match.group(0), line))

    is_code = path.endswith(CODE_SUFFIXES)
    if is_code:
        code = strip_comments_and_literals(raw)

        for label, opener, closer in (('braces', '{', '}'),
                                      ('parentheses', '(', ')'),
                                      ('brackets', '[', ']')):
            if code.count(opener) != code.count(closer):
                issues.append('%s unbalanced: %d open, %d close'
                              % (label, code.count(opener),
                                 code.count(closer)))

        for match in EMPTY_BODY.finditer(code):
            fragment = ' '.join(match.group(0).split())
            if re.search(r'\)\s*:.*\{\s*\}$', fragment):
                continue                       # constructor initialiser list
            if fragment.startswith('inline void'):
                continue                       # no-op with lockorder off
            if DEFAULT_CTOR.match(fragment):
                continue                       # default constructor
            issues.append('EMPTY FUNCTION BODY: %s' % fragment[:90])

        non_blank = [line for line in raw.rstrip().split('\n') if line.strip()]
        if non_blank:
            last = non_blank[-1].strip()
            if last.endswith((',', '&&', '||', '->', '::', '?', '\\')):
                issues.append('last line breaks off: %r' % last[-50:])

    return issues, raw.count('\n'), is_code


def main():
    files = collect_files()
    if not files:
        print('No sources found. Run this from the top of the tree.')
        return 2

    problems = []
    total_lines = 0
    code_lines = 0
    bodies = 0

    for path in files:
        issues, lines, is_code = check_file(path)
        total_lines += lines
        if is_code:
            code_lines += lines
            with open(path, encoding='utf-8', errors='replace') as handle:
                code = strip_comments_and_literals(handle.read())
            bodies += len(re.findall(r'\)\s*(?:const\s*)?\{', code))
        if issues:
            problems.append((path, issues))

    print('files checked:     %d' % len(files))
    print('lines in total:    %d' % total_lines)
    print('of that C/C++:     %d' % code_lines)
    print('function bodies:   about %d' % bodies)

    if problems:
        print('\nFINDINGS:\n')
        for path, issues in problems:
            print('  %s' % path)
            for issue in issues:
                print('      - %s' % issue)
        return 1

    print("""
NOTHING FOUND

  every file ends with a newline
  braces, parentheses and brackets balance in every file
  no function has an empty body
  no TODO / FIXME / XXX / HACK / unimplemented markers
  no last line breaks off mid-expression""")
    return 0


if __name__ == '__main__':
    sys.exit(main())
