

import os
import re

# Regex to match fenced code blocks ```...```
FENCED_BLOCK_RE = re.compile(
    r"(^```[\s\S]*?^```)",
    re.MULTILINE
)

RAW_START = "{% raw %}"
RAW_END = "{% endraw %}"


def already_wrapped(text, start, end):
    """
    Check whether the fenced block is already inside {% raw %} ... {% endraw %}
    by looking around the match.
    """
    before = text[:start]
    after = text[end:]

    last_raw_start = before.rfind(RAW_START)
    last_raw_end = before.rfind(RAW_END)

    # If the last raw start is after the last raw end, we are inside raw
    if last_raw_start != -1 and last_raw_start > last_raw_end:
        # Also ensure there is a closing endraw later
        if RAW_END in after:
            return True

    return False


def process_file(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    modified = False
    new_content = content
    offset = 0

    for match in FENCED_BLOCK_RE.finditer(content):
        start, end = match.span()
        start += offset
        end += offset

        if already_wrapped(new_content, start, end):
            continue

        block = new_content[start:end]
        wrapped = f"{RAW_START}\n{block}\n{RAW_END}"

        new_content = (
            new_content[:start] +
            wrapped +
            new_content[end:]
        )

        offset += len(wrapped) - len(block)
        modified = True

    if modified:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_content)
        print(f"Modified: {path}")


def main():
    for root, _, files in os.walk("."):
        for name in files:
            if name.endswith((".md", ".markdown")):
                process_file(os.path.join(root, name))


if __name__ == "__main__":
    main()

