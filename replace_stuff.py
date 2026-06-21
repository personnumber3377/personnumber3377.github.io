import os
import re

FENCED_BLOCK_RE = re.compile(
    r"(^```[\s\S]*?^```)",
    re.MULTILINE
)

RAW_REGION_RE = re.compile(
    r"{%\s*raw\s*%}[\s\S]*?{%\s*endraw\s*%}",
    re.MULTILINE
)

RAW_START = "{% raw %}"
RAW_END = "{% endraw %}"


def get_raw_regions(text):
    return [m.span() for m in RAW_REGION_RE.finditer(text)]


def inside_raw(start, end, raw_regions):
    for raw_start, raw_end in raw_regions:
        if start >= raw_start and end <= raw_end:
            return True
    return False


def process_file(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    raw_regions = get_raw_regions(content)

    replacements = []

    for match in FENCED_BLOCK_RE.finditer(content):
        start, end = match.span()

        if inside_raw(start, end, raw_regions):
            continue

        block = match.group(0)

        replacements.append(
            (start, end,
             f"{RAW_START}\n{block}\n{RAW_END}")
        )

    if not replacements:
        return

    new_content = content

    for start, end, replacement in reversed(replacements):
        new_content = (
            new_content[:start]
            + replacement
            + new_content[end:]
        )

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