# mailrecon launch post — r/netsec

> Note: r/netsec is strict. Posts must link directly to technical content (the repo/README), title format matters, and self-promo gets removed fast. Lead with the technique, not the tool. The repo README does the selling. Flair: "Tool".

---

## Title

mailrecon — passive email-auth recon that catches the "register the DMARC typo, receive the reports" attack

---

## Body

I kept finding the same silent DNS failures on assessments and bug bounty triage, and almost nobody checks them. So I built a small tool around the checks I run by hand.

The one that surprised people most: **registrable DMARC report destinations.** If a domain's `rua=`/`ruf=` points at an address on a domain that's expired or never registered, you can register that domain and start receiving its aggregate reports. You learn the sending sources, volumes, and failure patterns of a domain you don't own. It's a real recon channel and it sits in plain sight in a TXT record.

It also flags the quieter stuff:

- duplicate DMARC records, which silently void enforcement (RFC says multiple records means no policy applies)
- wide-open SPF (`+all` / overly broad includes / the 10-lookup limit blowing the record)
- dangling CNAMEs ripe for subdomain takeover, fingerprinted against can-i-take-over-xyz at runtime

**Passive by default.** With no scope file it sends zero traffic to the target. It only queries public DNS resolvers, RDAP, and certificate-transparency logs. Active checks (HTTP takeover confirmation) are gated behind an explicit, logged authorization file, and the mode banner prints to stderr on every run so you always know what class of traffic you're sending.

TypeScript, runs on bun, MIT. Single-domain markdown reports or bulk scope-file triage to ranked CSV.

Repo + full check list: https://github.com/donovan-sec/mailrecon

Happy to take feedback on the takeover fingerprinting and the SPF edge cases — that's where I expect the misses.
