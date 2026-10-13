"""Read-only helpers for the Markdown formats that the validator parses (headings, tables, row IDs)."""
import re

ROW_ID = re.compile(r'^\| ([A-Z][A-Za-z0-9]*-[0-9]{2,3}[A-Za-z]?) \|', re.M)


def cells(line):
    return [cell.strip() for cell in line.strip().strip('|').split('|')]


def tables(text):
    """Yield (header cells, list of row cells) for every pipe table in the text."""
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        following = lines[index + 1] if index + 1 < len(lines) else ''
        if line.startswith('|') and re.match(r'^\|\s*:?-{3,}', following):
            header = cells(line)
            rows = []
            index += 2
            while index < len(lines) and lines[index].startswith('|'):
                rows.append(cells(lines[index]))
                index += 1
            yield header, rows
            continue
        index += 1


def tables_with(text, required_columns):
    """Tables whose header contains all required columns, as lists of row dicts."""
    for header, rows in tables(text):
        if all(column in header for column in required_columns):
            yield [dict(zip(header, row)) for row in rows]


def table_exact(text, header):
    """Rows of tables whose header equals the given cells exactly."""
    found = []
    for columns, rows in tables(text):
        if columns == header:
            found.extend(dict(zip(columns, row)) for row in rows)
    return found


def headings(text):
    return {match.group(2).strip() for match in re.finditer(r'^(##|###) (.+)$', text, re.M)}


def row_ids(text):
    return set(ROW_ID.findall(text))
