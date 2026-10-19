"""Best-effort source line attribution for Terraform text.

Rules receive parsed HCL (which carries no line numbers), so findings are mapped back to
the source by locating the specific resource block and searching only inside it. This
avoids reporting the first textual match anywhere in the file.

Limitations: heredoc bodies and string templates containing unbalanced quotes or braces
can confuse block matching. When a block cannot be located, callers fall back to ``None``.
"""

import re

# Inclusive, zero-based (first_line_index, last_line_index).
Span = tuple[int, int]


def _is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("#") or stripped.startswith("//")


def _block_end(lines: list[str], start: int) -> int:
    """Return the index of the line that closes the block opened at ``start``.

    Quoted strings and comments are skipped so braces inside them are not counted. If the
    braces never balance, the last line of the file is returned.
    """
    depth = 0
    opened = False
    in_block_comment = False
    for index in range(start, len(lines)):
        line = lines[index]
        in_string = False
        pos = 0
        while pos < len(line):
            char = line[pos]
            pair = line[pos : pos + 2]
            if in_block_comment:
                if pair == "*/":
                    in_block_comment = False
                    pos += 1
            elif in_string:
                if char == "\\":
                    pos += 1
                elif char == '"':
                    in_string = False
            elif pair == "/*":
                in_block_comment = True
                pos += 1
            elif char == "#" or pair == "//":
                break
            elif char == '"':
                in_string = True
            elif char == "{":
                depth += 1
                opened = True
            elif char == "}":
                depth -= 1
                if opened and depth == 0:
                    return index
            pos += 1
    return len(lines) - 1


def find_resource_span(lines: list[str], resource_type: str, name: str) -> Span | None:
    """Locate ``resource "<type>" "<name>" { ... }`` and return its line span."""
    header = re.compile(rf'^\s*resource\s+"{re.escape(resource_type)}"\s+"{re.escape(name)}"\s*\{{')
    for index, line in enumerate(lines):
        if header.match(line):
            return index, _block_end(lines, index)
    return None


def child_block_spans(lines: list[str], span: Span, keyword: str) -> list[Span]:
    """Return spans of ``keyword { ... }`` blocks nested directly inside ``span``, in order."""
    opener = re.compile(rf"^\s*{re.escape(keyword)}\s*\{{")
    spans: list[Span] = []
    index = span[0] + 1
    while index < span[1]:
        if opener.match(lines[index]):
            end = _block_end(lines, index)
            spans.append((index, end))
            index = end + 1
        else:
            index += 1
    return spans


def find_line(lines: list[str], span: Span, pattern: str) -> int | None:
    """Return the 1-based number of the first non-comment line in ``span`` matching ``pattern``."""
    regex = re.compile(pattern)
    for index in range(span[0], span[1] + 1):
        if not _is_comment(lines[index]) and regex.search(lines[index]):
            return index + 1
    return None
