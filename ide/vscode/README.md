# Pepper SAST for VS Code

Pepper's security findings in your editor: AI SAST, secrets, dependency and logic-flaw
findings from your Pepper server, on the lines they are about.

- **Diagnostics** in the editor and the Problems panel, from the latest scan of your branch.
  They move with the code as you edit, and are marked "code may have changed since the scan"
  when Pepper can't find the code again.
- **Hover** for the details: why it is exploitable, the attack path and the fix.
- **Quick actions:** open in Pepper, mark in progress, mark resolved, copy the finding (for
  a ticket or your AI assistant).
- **Check on save:** each saved file is checked for secrets and risky patterns in about a
  second, with no AI.
- **Rescan** your repository, or **scan your working tree** before you push, from the
  command palette.
- **Status bar:** open critical, high and medium counts. Click to refresh.

Works with sast.votal.ai and on-prem Pepper, including behind a proxy or an internal CA. It
also works in Cursor and Windsurf.

## Getting started

1. Run **Pepper: Sign in** from the command palette.
2. Enter your Pepper server URL (for example `https://sast.votal.ai`).
3. Enter an API key, which you create in Pepper under **Settings → API keys**.

Pepper matches your folder to a Pepper repository by its git remote. If it can't, it asks
you to pick one (you can change it later with **Pepper: Select repository for this
folder**).

## Commands

| Command | |
|---|---|
| Pepper: Refresh findings | Fetch the latest scan's findings |
| Pepper: Rescan repository | Rescan the repository on the Pepper server (it clones the branch) and show the new results |
| Pepper: Scan working tree | Upload your working tree (tracked and untracked, not ignored files) and scan it. It asks before uploading. The results go to a separate repository, `<name> (local · <you>)`, so your CI history isn't affected |
| Pepper: Select repository for this folder | Change which Pepper repository a folder shows |
| Pepper: Open latest scan in Pepper | Open the scan in your browser |
| Pepper: Sign in / Sign out | Store or forget the API key |

## Settings

| Setting | Default | |
|---|---|---|
| `pepper.serverUrl` | `https://sast.votal.ai` | Your Pepper server (https:// only, except localhost) |
| `pepper.minSeverity` | `LOW` | Lowest severity shown |
| `pepper.checkOnSave` | `true` | Send saved files to your Pepper server for the instant check |
| `pepper.branch` | (current branch) | Show findings from this branch's latest scan |
| `pepper.refreshMinutes` | `10` | Background refresh interval (0 turns it off) |
| `pepper.caFile` | | PEM file of an internal CA |

A proxy is picked up from `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`.

## Privacy and security

- **API key:** kept in VS Code's secret storage. It is never written to settings or logs.
- **What is sent to your Pepper server:** the saved file (for the check on save, which you
  can turn off), and your working tree (only when you run **Scan working tree** and
  confirm).
- **No telemetry.**
- **Untrusted workspaces:** in Restricted Mode, the extension doesn't run git or send any
  files.
