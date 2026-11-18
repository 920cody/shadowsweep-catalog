# ShadowSweep detection catalog

This repository publishes the signed list of AI tools that ShadowSweep recognizes. It runs itself:

| When | What happens | What you do |
|---|---|---|
| Every Monday | GitHub looks for popular new AI extensions, drafts entries, checks them, and opens a pull request titled **New AI tools found**. GitHub emails you. | Open it, look over the table, click **Merge pull request**. Or close it to skip. |
| When you merge | The catalog is checked, given a new version number, signed with your key, and published to GitHub Pages. | Nothing. ShadowSweep users get it within a day. |
| Quiet weeks | The check is recorded so GitHub keeps the schedule running. | Nothing. |

## Files

- `catalog.json`: the catalog itself (AI tools, apps with built-in AI, AI engine files).
- `safe-app-names.txt`: common apps that are **not** AI tools. Publishing is blocked if any AI pattern matches one of them, which prevents false alarms. If a customer reports a false alarm, add the app's name here.
- `signer/`: the checking and signing tool (the same code as `sswkeygen`).
- `scripts/discover.py`: the weekly discovery job.

## Changing something by hand

Open `catalog.json` on GitHub, click the pencil icon, make the change, and click **Commit changes**. The checks run before anything is published; if something's wrong, the run under **Actions** shows a red X with a plain-English reason, and nothing reaches customers.

Entries are checked from the top down and the first match wins, so put specific entries above general ones. The checks will tell you if an entry is in the wrong place.

## Secrets (Settings › Secrets and variables › Actions)

- `SSW_PRIVATE_KEY`: your signing key. Required.
- `ANTHROPIC_API_KEY`: optional. Lets Claude write descriptions and ratings for newly found tools and drop ones that aren't really AI.
