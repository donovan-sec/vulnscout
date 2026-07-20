# OwnerMap launch post — r/sysadmin

> Note: r/sysadmin rewards "I built a free thing that solves a pain you have" when it's genuinely free and no-strings. Lead with the pain, keep it humble, no marketing voice. Single-file HTML + zero install is the hook that makes people actually try it. Mention the audit angle but don't oversell. Good crosspost targets after: r/AzureAD, r/Intune, r/entra.

---

## Title

I built a free single-file tool that finds every Entra ID group with no owner (before your auditor does)

---

## Body

Every time an audit rolls around (SOX, ISO 27001, NIST), the same question comes up: who owns this group, and who approves access to it? And in most tenants the honest answer is "nobody, because group ownership was never assigned systematically." It's the forgotten first step of every access-request process.

I got tired of stitching together Graph queries to answer it, so I built **OwnerMap.**

It's a single `.html` file. No install, no npm, no agent, nothing to deploy. You open it in any browser, sign in (delegated as yourself, or with an app registration), and it:

- enumerates every group in the tenant, paginating through thousands of them
- resolves owners and members concurrently with automatic throttle/retry handling
- flags every group with **no owner** as HIGH risk with red callouts
- shows your owner-coverage percentage at a glance
- lets you filter (No Owner / Security / M365 / On-Prem), search, sort, and expand rows to see full member lists
- exports the whole thing to CSV for ticket generation or offline review

It runs entirely in your browser against Microsoft Graph. Nothing gets sent anywhere except Microsoft. OS-agnostic because it's just an HTML file.

It's free and MIT licensed. Setup is one app registration (or just delegated sign-in if you'd rather not), and the README walks through it step by step.

Repo + screenshots: https://github.com/donovan-sec/OwnerMap

If you try it on a real tenant I'd genuinely like to hear where it chokes — big tenants and weird group types are where I expect edge cases.
