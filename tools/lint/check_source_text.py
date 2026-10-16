"""Fails when source files contain invisible or bidirectional control characters (Trojan Source, CVE-2021-42574).

Such characters belong in code only as escapes like \\u202E. Run: python3 -I tools/lint/check_source_text.py
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SUFFIXES = {'.cs', '.csproj', '.props', '.sql', '.json', '.ts', '.tsx', '.js', '.css', '.html', '.bicep', '.py', '.yml', '.md'}
SKIP = {'bin', 'obj', 'node_modules', 'dist', '.git', '.claude'}
FORBIDDEN = set(range(0x200B, 0x2010)) | set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x061C, 0xFEFF, 0x00AD}


def main() -> int:
    problems = []
    for folder in ('src', 'tests', 'tools', 'portal', 'infra', '.github'):
        base = ROOT / folder
        if not base.exists():
            continue
        for path in base.rglob('*'):
            if not path.is_file() or path.suffix not in SUFFIXES or SKIP.intersection(path.relative_to(ROOT).parts):
                continue
            text = path.read_text(encoding='utf-8')
            for number, line in enumerate(text.splitlines(), 1):
                found = sorted({f'U+{ord(c):04X}' for c in line if ord(c) in FORBIDDEN or (ord(c) < 32 and c != '\t')})
                if found:
                    problems.append(f'{path.relative_to(ROOT)}:{number}: {", ".join(found)}')
    for problem in problems:
        print(f'[source-text] {problem}')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
