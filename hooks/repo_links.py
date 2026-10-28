"""Hook MkDocs : réécrit les liens Markdown qui sortent de docs/ (configs/, scripts/, README
racine…) en liens vers le fichier sur GitHub, pour qu'ils ne cassent pas sur le site."""
import os
import re

REPO = "https://github.com/Drien95/SIEM_PROJECT/blob/main/"
LINK = re.compile(r"(\]\()([^)\s#]+)(#[^)\s]*)?(\))")


def on_page_markdown(markdown, page, config, files):
    docs_dir = os.path.abspath(config["docs_dir"])
    root = os.path.dirname(docs_dir)
    page_dir = os.path.dirname(os.path.join(docs_dir, page.file.src_path))

    def fix(m):
        target = m.group(2)
        if re.match(r"^[a-z]+:", target) or target.startswith("/"):
            return m.group(0)
        resolved = os.path.normpath(os.path.join(page_dir, target))
        if resolved.startswith(docs_dir + os.sep) or resolved == docs_dir:
            return m.group(0)
        rel = os.path.relpath(resolved, root).replace(os.sep, "/")
        if rel.startswith(".."):
            return m.group(0)
        return f"{m.group(1)}{REPO}{rel}{m.group(3) or ''}{m.group(4)}"

    return LINK.sub(fix, markdown)
