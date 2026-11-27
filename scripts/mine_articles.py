"""Index Vault documentation pages into src/data/vault-articles.json.

Reads the MDX sources of the latest Vault docs from a sparse clone of
hashicorp/web-unified-docs (see below). Each article carries its page title,
URL, doc section, and keyword text (title, description, headings) used by the
in-app ranker. Refresh with:

  git clone --depth 1 --filter=blob:none --sparse https://github.com/hashicorp/web-unified-docs ~/web-docs
  cd ~/web-docs && git sparse-checkout set content/vault/v2.x/content/docs content/vault/v2.x/content/api-docs
  python3 scripts/mine_articles.py
"""
import json, os, re, sys, subprocess

DOCS = os.path.expanduser(os.environ.get("WEBDOCS", "~/web-docs"))
VER = os.environ.get("VAULT_DOCS_VERSION", "v2.x")
ROOT = os.path.join(DOCS, "content", "vault", VER, "content")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "data", "vault-articles.json")

def frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return {}, text
    fm = {}
    for line in m.group(1).splitlines():
        kv = re.match(r"^(page_title|description|layout):\s*(.+)", line)
        if kv:
            fm[kv.group(1)] = kv.group(2).strip().strip('"').rstrip(">-").strip()
    return fm, text[m.end():]

def main():
    subprocess.run(["git", "-C", DOCS, "pull", "-q"], capture_output=True)
    articles = []
    for base, urlprefix in (("docs", "docs"), ("api-docs", "api-docs")):
        for dirpath, _, files in os.walk(os.path.join(ROOT, base)):
            for f in sorted(files):
                if not f.endswith(".mdx"):
                    continue
                full = os.path.join(dirpath, f)
                rel = os.path.relpath(full, os.path.join(ROOT, base))[:-4]
                if "/partials/" in full or rel.endswith("/index"):
                    rel = rel[: -len("/index")] if rel.endswith("/index") else rel
                text = open(full, encoding="utf-8", errors="replace").read()
                fm, body = frontmatter(text)
                title = fm.get("page_title") or rel.split("/")[-1].replace("-", " ")
                headings = " ".join(re.findall(r"^#{1,3}\s+(.+)$", body, re.M)[:12])
                desc = fm.get("description", "")
                # strip mdx formatting noise from the keyword text
                kw = re.sub(r"[`*_~()\[\]#<>/\\]", " ", f"{title} {title} {desc} {headings}")
                kw = re.sub(r"\s+", " ", kw).strip()
                section = "/".join(rel.split("/")[:2]) if "/" in rel else rel
                articles.append({
                    "title": title,
                    "url": f"https://developer.hashicorp.com/vault/{urlprefix}/{rel}",
                    "section": section,
                    "keywords": kw[:600],
                })
    articles.sort(key=lambda a: a["url"])
    json.dump({"generated_from": f"hashicorp/web-unified-docs content/vault/{VER}", "articles": articles},
              open(OUT, "w"), indent=1)
    open(OUT, "a").write("\n")
    print(f"{len(articles)} articles indexed")

if __name__ == "__main__":
    main()
