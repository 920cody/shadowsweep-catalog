"""
Finds popular AI extensions that ShadowSweep doesn't recognize yet and adds draft entries to catalog.json.

Sources (public, no account needed):
  - Visual Studio Code Marketplace: the AI and Chat categories
  - Firefox Add-ons: searches for AI, ChatGPT, GPT and Copilot (most of these are also published for Chrome and Edge)

If the ANTHROPIC_API_KEY secret is set, Claude writes the descriptions and risk ratings and drops anything that
isn't really an AI tool. Without it, sensible defaults are used.

Every draft is checked with the same validator used before publishing; drafts that fail are dropped, so the
pull request this produces is always safe to merge. Standard library only.
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

CATALOG = "catalog.json"
MAX_NEW = 15
MIN_VSCODE_INSTALLS = 50_000
MIN_FIREFOX_USERS = 5_000
MODEL = "claude-haiku-5-5"
USER_AGENT = "ShadowSweep-catalog-discovery/1.0"

AI_WORDS = re.compile(r"\b(AI|GPT|LLM|LLMs|ChatGPT|Copilot|chatbot|Chatbot|Claude|Gemini|DeepSeek|Grok|Mistral|Ollama|AI-powered)\b")

CODING_EXPOSURE = ("Source code in the projects you open, terminal output, and anything you paste into its chat. "
                   "Some modes can run commands on your PC.")
BROWSER_EXPOSURE = "The content of web pages you visit, and anything you select or type while it is active."
TOOL_TYPES = ["AI coding assistant", "AI browser sidebar", "AI writing assistant", "AI chat assistant",
              "AI meeting recorder", "AI agent", "AI screen & activity recorder", "AI companion app"]


def http_json(url, data=None, headers=None, timeout=30):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def log(msg):
    print(msg, flush=True)


# ---------------- Sources ----------------

def vscode_candidates():
    found = []
    for category in ("AI", "Chat"):
        body = {
            "filters": [{
                "criteria": [
                    {"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
                    {"filterType": 5, "value": category},
                ],
                "pageNumber": 1, "pageSize": 100, "sortBy": 4, "sortOrder": 0,
            }],
            "flags": 914,
        }
        try:
            data = http_json(
                "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery",
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json", "Accept": "application/json;api-version=3.0-preview.1"})
        except (urllib.error.URLError, TimeoutError, ValueError) as ex:
            log(f"VS Code Marketplace ({category}) unavailable: {ex}")
            continue
        for ext in data.get("results", [{}])[0].get("extensions", []):
            installs = 0
            for stat in ext.get("statistics", []):
                if stat.get("statisticName") == "install":
                    installs = int(stat.get("value", 0))
            publisher = ext.get("publisher", {}).get("publisherName", "")
            name = ext.get("extensionName", "")
            found.append({
                "source": "VS Code Marketplace",
                "name": (ext.get("displayName") or name).strip(),
                "id": f"{publisher}.{name}",
                "vendor": ext.get("publisher", {}).get("displayName") or publisher,
                "description": (ext.get("shortDescription") or "").strip(),
                "users": installs,
                "url": f"https://marketplace.visualstudio.com/items?itemName={publisher}.{name}",
                "broad": False,
            })
    return [c for c in found if c["users"] >= MIN_VSCODE_INSTALLS]


def firefox_candidates():
    found = []
    for query in ("AI", "ChatGPT", "GPT", "Copilot"):
        url = ("https://addons.mozilla.org/api/v5/addons/search/?" +
               urllib.parse.urlencode({"q": query, "type": "extension", "sort": "users", "page_size": 50, "lang": "en-US"}))
        try:
            data = http_json(url)
        except (urllib.error.URLError, TimeoutError, ValueError) as ex:
            log(f"Firefox Add-ons ({query}) unavailable: {ex}")
            continue
        for addon in data.get("results", []):
            def text(field):
                value = addon.get(field) or ""
                if isinstance(value, dict):
                    value = value.get("en-US") or next(iter(value.values()), "")
                return (value or "").strip()

            permissions = []
            try:
                file = addon.get("current_version", {}).get("file", {})
                permissions = (file.get("permissions") or []) + (file.get("host_permissions") or [])
            except AttributeError:
                pass
            broad = any(p == "<all_urls>" or str(p).startswith("*://*/") for p in permissions)
            authors = addon.get("authors") or []
            found.append({
                "source": "Firefox Add-ons",
                "name": text("name"),
                "id": addon.get("guid") or "",
                "vendor": (authors[0].get("name") if authors else "") or "Unknown developer",
                "description": text("summary"),
                "users": int(addon.get("average_daily_users") or 0),
                "url": addon.get("url") or "",
                "broad": broad,
            })
    return [c for c in found if c["users"] >= MIN_FIREFOX_USERS]


# ---------------- Matching against the existing catalog ----------------

def to_python_regex(pattern):
    # .NET and Python agree on everything the catalog uses; this just guards against odd cases.
    return re.compile(pattern, re.IGNORECASE)


def already_known(candidate, signatures):
    fields = [candidate["name"], candidate["id"]]
    for sig in signatures:
        try:
            pattern = to_python_regex(sig["pattern"])
            exclude = to_python_regex(sig["exclude"]) if sig.get("exclude") else None
        except re.error:
            continue
        for field in fields:
            if field and pattern.search(field) and not (exclude and exclude.search(field)):
                return True
    return False


def slug(text, taken):
    base = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "tool"
    candidate, n = base, 2
    while candidate in taken:
        candidate, n = f"{base}-{n}", n + 1
    taken.add(candidate)
    return candidate


def literal(text):
    # Match the exact name, not inside a longer word. Works in both .NET and Python.
    return r"(?<!\w)" + re.escape(text) + r"(?!\w)"


def draft_entry(c, taken):
    alternatives = [literal(c["name"])]
    if c["source"] == "VS Code Marketplace" and c["id"]:
        alternatives.insert(0, "^" + re.escape(c["id"]) + "$")
    elif c["id"] and len(c["id"]) > 4:
        alternatives.append("^" + re.escape(c["id"]) + "$")
    coding = c["source"] == "VS Code Marketplace"
    return {
        "id": slug(c["name"], taken),
        "name": c["name"][:80],
        "vendor": c["vendor"][:80] or "Unknown developer",
        "toolType": "AI coding assistant" if coding else "AI browser sidebar",
        "risk": "High" if c["broad"] else "Medium",
        "dataExposure": CODING_EXPOSURE if coding else BROWSER_EXPOSURE,
        "pattern": "|".join(alternatives),
        "exclude": None,
        "domains": [],
        "examples": [c["name"]],
        "_source": c,
    }


# ---------------- Optional: Claude reviews the drafts ----------------

def review_with_claude(drafts):
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key or not drafts:
        return drafts
    items = [{"id": d["id"], "name": d["name"], "source": d["_source"]["source"], "publisher": d["vendor"],
              "description": d["_source"]["description"][:400], "readsAllWebsites": d["_source"]["broad"]} for d in drafts]
    prompt = (
        "You help maintain ShadowSweep, which tells consumers which AI tools on their PC can reach their data. "
        "For each item below, decide whether it is genuinely an AI tool (it sends user content to an AI model, or runs one). "
        f"Reply with only a JSON array. Each element: {{\"id\": same id, \"isAiTool\": true/false, "
        f"\"toolType\": one of {json.dumps(TOOL_TYPES)}, \"risk\": one of [\"Low\",\"Medium\",\"High\",\"Critical\"], "
        "\"dataExposure\": one plain-English sentence on what data it can see, \"vendor\": the company or developer}. "
        "Use High when it can read every website or records audio/screen; Critical only for always-on screen or audio recording.\n\n"
        + json.dumps(items, ensure_ascii=False))
    body = {"model": MODEL, "max_tokens": 4000, "messages": [{"role": "user", "content": prompt}]}
    try:
        data = http_json("https://api.anthropic.com/v1/messages", data=json.dumps(body).encode(),
                         headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                         timeout=120)
        text = "".join(part.get("text", "") for part in data.get("content", []))
        reviews = {r["id"]: r for r in json.loads(text[text.index("["): text.rindex("]") + 1])}
    except Exception as ex:  # noqa: BLE001 - any failure falls back to the defaults
        log(f"Claude review skipped ({ex}); using default descriptions.")
        return drafts

    kept = []
    for d in drafts:
        r = reviews.get(d["id"])
        if r is None:
            kept.append(d)
            continue
        if not r.get("isAiTool", True):
            log(f"Dropped (not an AI tool): {d['name']}")
            continue
        if r.get("toolType") in TOOL_TYPES:
            d["toolType"] = r["toolType"]
        if r.get("risk") in ("Low", "Medium", "High", "Critical"):
            d["risk"] = r["risk"]
        if isinstance(r.get("dataExposure"), str) and 10 < len(r["dataExposure"]) < 300:
            d["dataExposure"] = r["dataExposure"].strip()
        if isinstance(r.get("vendor"), str) and 0 < len(r["vendor"]) < 80:
            d["vendor"] = r["vendor"].strip()
        kept.append(d)
    return kept


# ---------------- Validation with the real (.NET) checker ----------------

def validate(catalog):
    with open(CATALOG, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2, ensure_ascii=False)
        f.write("\n")
    result = subprocess.run(["dotnet", os.environ["SIGNER"], "catalog-validate", "--in", CATALOG, "--json"],
                            capture_output=True, text=True)
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"ok": False, "errors": [result.stdout + result.stderr]}


def main():
    with open(CATALOG, encoding="utf-8") as f:
        original_text = f.read()
    catalog = json.loads(original_text)
    signatures = catalog["signatures"]

    candidates = vscode_candidates() + firefox_candidates()
    log(f"Found {len(candidates)} popular candidates.")

    seen, fresh = set(), []
    for c in sorted(candidates, key=lambda c: -c["users"]):
        key = c["name"].lower()
        if not c["name"] or key in seen:
            continue
        seen.add(key)
        if "shadowsweep" in key:
            continue
        if not (AI_WORDS.search(c["name"]) or AI_WORDS.search(c["description"])):
            continue
        if already_known(c, signatures):
            continue
        fresh.append(c)
    log(f"{len(fresh)} aren't recognized yet.")

    taken = {s["id"] for s in signatures}
    drafts = [draft_entry(c, taken) for c in fresh[:MAX_NEW * 2]]
    drafts = review_with_claude(drafts)[:MAX_NEW]

    # New, very specific entries go first so broader entries (like "ChatGPT") don't claim them.
    accepted = list(drafts)
    for attempt in range(6):
        trial = dict(catalog)
        trial["signatures"] = [{k: v for k, v in d.items() if k != "_source"} for d in accepted] + signatures
        check = validate(trial)
        if check.get("ok"):
            break
        bad = {d["id"] for d in accepted if any(f'"{d["id"]}"' in e for e in check.get("errors", []))}
        if not bad:
            log("The catalog failed its checks for a reason unrelated to the new entries:")
            for e in check.get("errors", []):
                log("  " + e)
            accepted = []
        else:
            for d in accepted:
                if d["id"] in bad:
                    log(f"Dropped (failed checks): {d['name']}")
            accepted = [d for d in accepted if d["id"] not in bad]
    else:
        accepted = []

    if accepted:
        final = dict(catalog)
        final["signatures"] = [{k: v for k, v in d.items() if k != "_source"} for d in accepted] + signatures
        with open(CATALOG, "w", encoding="utf-8") as f:
            json.dump(final, f, indent=2, ensure_ascii=False)
            f.write("\n")
    else:
        # Put the file back exactly as it was, so no empty pull request is opened.
        with open(CATALOG, "w", encoding="utf-8", newline="") as f:
            f.write(original_text)

    lines = ["ShadowSweep found popular AI tools it doesn't recognize yet. Each one below has been checked automatically "
             "(pattern works, no false alarms on common apps, correct order).", "",
             "**Merge this pull request** to publish them to every ShadowSweep user. Close it to skip them this week.", "",
             "| Tool | Where it's from | Users | Rated | What it can see |",
             "|---|---|---|---|---|"]
    for d in accepted:
        c = d["_source"]
        link = f"[{d['name']}]({c['url']})" if c["url"] else d["name"]
        lines.append(f"| {link} | {c['source']} | {c['users']:,} | {d['risk']} | {d['dataExposure']} |")
    if not accepted:
        lines.append("| (none) | | | | |")
    lines += ["", "To change a rating or wording, open **Files changed**, click the three dots on catalog.json, "
              "choose **Edit file**, and commit the change to this branch before merging."]
    report = os.environ.get("REPORT", "discovery-report.md")
    with open(report, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log(f"Added {len(accepted)} new AI tools.")


if __name__ == "__main__":
    sys.exit(main())
