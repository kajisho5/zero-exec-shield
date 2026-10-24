English | [日本語](ioc-verification.ja.md)

# ZES v5.2 IoC primary-source verification report

- **Survey date**: 2026-10-22
- **Scope**: ZES v5.2 Master Specification §3 (the data in `rules/ioc.json`) + some values referenced in §6 / §9
- **Method**: compared against official advisories (GitHub Advisory / OSV / NVD / CISA KEV / vendor notices) and the original researchers (Socket, StepSecurity, JFrog, Wiz, Snyk, Datadog, Microsoft, Unit 42, Check Point, Elastic, Pillar, Adversa and others) through web searches. For some items the article body could not be retrieved directly and the search-result summary was used. Values not stated by the sources were not filled in by guessing.
- **Verdict categories**
  - **Match**: the specification's value was confirmed by a primary source or by several original researchers
  - **Differs**: part of the facts was confirmed, but the value, attribution or description disagrees with the specification (details in the notes column)
  - **Could not confirm**: no corroboration was found within the scope of this survey, or the item was not investigated

## Summary

| Verdict | Count | Share |
|---|---|---|
| Match | 68 | about 59% |
| Differs | 24 | about 21% |
| Could not confirm | 23 | about 20% |
| **Total** | **115** | 100% |

(Counted per row of the tables below)

**Main differences that affect the implementation (by priority)**

1. **Mixed-up campaign names and timing**: telnyx (2026-03-27) and lightning (2026-04-30), included in `pypi-oct2026`, are neither October incidents. certifi belongs to the eMudhra incident (GHSA-6q48-6c7w-9gw2) and not to the `litellm-oct2026` campaign.
2. **Malicious versions of jscrambler**: there are actually 5 versions: 8.14.0 / 8.16.0 / 8.17.0 / 8.18.0 / 8.20.0. Matching on the range "8.14.0–8.20.0" also falsely flags 8.15.0 and 8.19.0, which have not been reported as malicious. The safe version is 8.22.0. Attribution to TeamPCP could not be confirmed (JFrog assesses it as part of the IronWorm lineage).
3. **trivy-action v0.69.4**: v0.69.4 is a version number of the Trivy binary, not of trivy-action. In trivy-action, tags 75/76 were rewritten (76/77 according to Aqua's announcement), and the safe version is v0.35.0.
4. **The fixed version for Cursor CVE-2026-50548 is 3.0** (the "<2.5" in specification §41 belongs to CVE-2026-26268).
5. **The product affected by CVE-2026-22703 is Cosign, not Rekor**. The version ranges <2.6.2 / <3.0.4 match.
6. **Wrong descriptions of MCP CVEs**: CVE-2026-52869 is a flaw in the MCP Python SDK that does not bind the session ID to the authenticated principal (CVSS 7.1, fixed in 1.27.2), not a registry-poisoning incident. CVE-2026-58500 is an XSS in appium-mcp (8.2), and no source describes it as RCE. GO-2026-6002 is not a NAT64 flaw (it is an SSRF in the auth discovery path, CVE-2026-58196).
7. **Definition of NeighborJack**: in Backslash Security's report (2025-06) it refers to the misconfiguration where "an MCP server binds to 0.0.0.0 and is reachable from the same LAN". This is a different detection target from the specification's "indirect compromise via an adjacent vulnerable MCP / registration of internal IPs".
8. **False-positive risk**: `seed1/seed2.getsession.org` (legitimate infrastructure of the Session messenger) and `eth-mainnet.nodereal.io` / `go.getblock.io` / `eth.llamarpc.com` (legitimate Ethereum RPC) cause false positives if their mere appearance is rated CRITICAL.
9. **Missing ChainDrop IoCs**: the new C2 `awqhnjewqjkl[.]icu` and the Ethereum resolver contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103` are not in the specification (Unit 42 / Elastic / Microsoft).
10. **Homebrew ca-certificates `2026-09-25_1`**: the eMudhra key leak was reported on 2026-10-17. A bundle dated before that cannot be the fixed version, so the value is suspected to be wrong (not corroborated).

---

## 1. `packages[]`

| Item | Specification value | Primary-source value | Verdict | Source URL |
|---|---|---|---|---|
| litellm (malicious version / safe version) | 1.107.0 / 1.106.2 | 7 wheels of 1.107.0 are malicious. Published 2026-10-21; safe version 1.106.2 (Chainguard) | Match | https://research.jfrog.com/post/litellm-hijacked-again/ , https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer , https://www.chainguard.dev/unchained/litellm-attacked-again-malicious-1-107-0-wheels-on-pypi-and-docker-hub-october-2026 |
| litellm (malicious files) | cook.pth / cook.py / sitecustomize.py | cook.pth (`import cook`) → cook.py, a daemon in sitecustomize.py, `/tmp/remote_code_loader.lock` | Match | https://www.mend.io/blog/litellm-1-107-0-compromised/ , https://www.endorlabs.com/learn/litellm-1-107-0-compromised-python-startup-hooks-steal-cloud-ai-and-proxy-credentials |
| litellm (Docker image) | Not stated | The Docker Hub image was also compromised (StepSecurity / Chainguard) | Differs (missing from the specification) | https://socket.dev/blog/litellm-compromise |
| certifi | <2026.10.19 / 2026.10.19 (campaign: litellm-oct2026) | GHSA-6q48-6c7w-9gw2. Affected range 2019.03.09 to <2026.10.19 (removes emSign ECC Root CA G3). Caused by the eMudhra incident, unrelated to LiteLLM | Differs (wrong campaign link) | https://www.openwall.com/lists/oss-security/2026/10/20/20 , https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576 |
| @tanstack/* (scale) | 42pkg / 84ver | 42 packages and 84 versions published on 2026-05-11. GHSA-g7cv-rxg3-hmpx / CVE-2026-45321 | Match | https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack , https://advisories.gitlab.com/npm/@tanstack/react-router/CVE-2026-45321/ |
| @tanstack/* (malicious files) | router_init.js / tanstack_runner.js / vite_setup.mjs | The file names could not be checked in this survey | Could not confirm | — |
| mistralai | 2.4.6 / 2.4.5 | mistralai 2.4.6 on PyPI is malicious; 2.4.5 is safe | Match | https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised , https://phoenix.security/mini-shai-hulud-teampcp-tanstack/ |
| guardrails-ai | 0.10.1 / 0.10.0 | 0.10.1 is malicious; 0.10.0 and earlier are safe | Match | https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack |
| intercom-client | Compromised version / "1,800+ developers affected" | The malicious version is 7.0.4 (2026-04-30, public for about 2 hours); the safe version is 7.0.3. GHSA-54pg-9963-v8vg. The figure "1,800+" is not found anywhere | Differs (version not stated, no corroboration for the number affected) | https://osv.dev/vulnerability/GHSA-54pg-9963-v8vg |
| jscrambler | 8.14.0–8.20.0 (campaign: teampcp) | 5 malicious versions: 8.14.0 / 8.16.0 / 8.17.0 / 8.18.0 / 8.20.0; safe version 8.22.0. A Rust infostealer published 2026-07-11. Attribution to TeamPCP could not be confirmed; JFrog assesses it as IronWorm lineage | Differs | https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html , https://www.attestd.io/blog/jscrambler-ironworm-npm-supply-chain |
| @asyncapi/* | Compromised versions | Not investigated | Could not confirm | — |
| @polymarket/* | Compromised versions | Not investigated | Could not confirm | — |
| keyv | 6.0.0 / latest 5.x | 6.0.0 published 2026-08-04 (MAL-2026-11524). npm restored keyv@5.6.0 as latest | Match | https://osv.dev/vulnerability/MAL-2026-11524 , https://www.chainguard.dev/unchained/the-keyv-and-cacheable-npm-supply-chain-attack-inside-the-mini-shai-hulud-campaign |
| flat-cache | 6.1.24 | 6.1.24 is malicious; 6.1.23 is safe | Match | https://www.stepsecurity.io/blog/chaindrop-npm-worm |
| file-entry-cache | 11.1.6 | Datadog / StepSecurity list 11.1.6 as malicious. Chainguard gives no version number | Match (sources partly differ) | https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/ |
| cacheable-request | 13.0.20 | 13.0.20 is malicious; 13.0.19 is safe | Match | https://www.stepsecurity.io/blog/chaindrop-npm-worm |
| cache-manager | 7.2.10 | 7.2.10 is malicious; 7.2.9 is safe | Match | https://www.chainguard.dev/unchained/the-keyv-and-cacheable-npm-supply-chain-attack-inside-the-mini-shai-hulud-campaign |
| ecto | 5.0.1 | setup.mjs and Math_Symbol.js in ecto@5.0.1 are byte-for-byte identical to those in keyv@6.0.0 | Match | https://www.mend.io/blog/keyv-malicious-packages/ |
| cacheable / @cacheable/memory / @cacheable/node-cache / @cacheable/utils / @cacheable/net | 2.5.1 / 2.2.1 / 3.1.2 / 2.5.1 / 2.1.1 | Listed as affected packages, but the individual versions could not be checked | Could not confirm | https://www.stepsecurity.io/blog/chaindrop-npm-worm |
| lightning | 2.6.2, 2.6.3 / 2.6.1 / `_runtime/` (campaign: pypi-oct2026) | The values match (`_runtime` downloads and runs Bun). However, it was published on 2026-04-30 and is not an October incident | Differs (campaign name, timing) | https://lightning.ai/blog/pytorch-lightning-supply-chain-attack/ , https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/ |
| telnyx | 4.87.1, 4.87.2 / 4.87.0 / 83.142.209.203:8080 (campaign: pypi-oct2026) | The values match (`http://83.142.209.203:8080/ringtone.wav`, GHSA-955r-262c-33jc). However, it was published on 2026-03-27 and is not an October incident | Differs (campaign name, timing) | https://advisories.gitlab.com/pypi/telnyx/GHSA-955r-262c-33jc/ , https://www.akamai.com/blog/security-research/telnyx-sdk-pypi-2026-teampcp-supply-chain-attacks |
| py2ops | 2.2 | Only Vulert lists it as malicious. secure.software's scan of 2.2.1 found no malware, so the two contradict each other. Version 2.2 could not be confirmed | Could not confirm | https://vulert.com/vuln-db/malicious-code-in-py2ops--pypi- , https://secure.software/pypi/packages/py2ops/malware |
| @solana-labs/web3js | 1.0.0, 1.0.2, 100+ / MAL-2026-5788 | MAL-2026-5788 (GHSA-pqhf-q5g8-6jpm, 2026-06-15). The version list differs by source (1.0.0–1.0.10, 1.98.103–1.98.110, 1.98.112, etc.) | Match (check the version list against the latest OSV entry) | https://osv.dev/vulnerability/MAL-2026-5788 |
| solana-web3-stable | sibling | MAL-2026-10903 | Match | https://www.hacktron.ai/package/npm/solana-web3-stable/1.0.0 |
| @solana-labs/spl-toke / web3-js / ancor | sibling | Could not be checked | Could not confirm | — |
| tensorlake | 0.5.144 (2026-10-08) | 0.5.144 published 2026-10-08; 0.5.143 is the last safe version. Runs at preinstall and has a switch that wipes $HOME when it detects token revocation | Match | https://socket.dev/blog/tensorlake-compromise , https://safedep.io/tensorlake-npm-compromise-mini-shai-hulud/ |
| imgdecode (malfex) | shellcode loader | Uploaded 2026-09-30. On Windows it injects shellcode into dllhost.exe through a DLL | Match | https://thehackernews.com/2026/10/malfex-npm-package-imgdecode-hides.html |
| Namastex Labs related | npm→PyPI→crypto assets | @automagik/genie, pgserve, etc. (2026-04). Spread to npm and PyPI and steals wallets | Match (timing is 2026-04) | https://www.theregister.com/2026/04/22/another_npm_supply_chain_attack/ |
| css-nesting-transform | 1.0.0 (2026-10-12) | MAL-2026-17804. Published on npm 2026-10-07, published in OSV 10-08, last updated 10-12. A reconnaissance package aimed at dependency confusion (sends whoami / id / uname to a webhook) | Differs (date) | https://osv.dev/vulnerability/MAL-2026-17804 , https://github.com/ossf/malicious-packages/pull/1602 |
| HF datasets | Malicious datasets (2026-07-16) | Disclosed by Hugging Face on 2026-07-16. Two vectors: a remote code loader and template injection in the dataset configuration | Match | https://huggingface.co/blog/security-incident-july-2026 |
| lerobot | CVE-2026-25874 / CVSS 9.8 | ≤0.5.1 affected. The CVSS differs by source: 9.3 (GHSA / THN) and 9.8 (CSA). No fixed version existed at disclosure | Differs (CVSS inconsistent between sources, fixed version not confirmed) | https://labs.cloudsecurityalliance.org/research/csa-research-note-lerobot-cve-2026-25874-unauth-rce-20260429/ , https://thehackernews.com/2026/04/critical-cve-2026-25874-leaves-hugging.html |
| megalodon-ci | 5,561 repositories (2026-05) | 2026-05-18: 5,718 commits to 5,561 repositories in under 6 hours | Match | https://labs.cloudsecurityalliance.org/research/csa-research-note-megalodon-github-actions-cicd-supply-chain , https://stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories |
| sckit-memos | OpenClaw / MemoryOS (2026-09-23) | npm @memtensor/memos-cloud-openclaw-plugin 0.1.21 / 0.1.23 / 0.1.25, PyPI MemoryOS 2.0.34. C2 is skyleen[.]fr (Socket) | Match (versions and C2 missing from the specification) | https://thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html , https://safedep.io/memtensor-sckit-worm-npm-pypi/ |
| @redhat-cloud-services/* | MAL-2026-5141 / OIDC publisher compromise | MAL-2026-5141 covers only one package, host-inventory-client 5.0.3 / 5.0.4 / 5.0.6. Other packages have separate IDs such as MAL-2026-5142 / 5143. The abuse of the OIDC trusted publisher matches | Match (the ID covers only one package) | https://osv.dev/vulnerability/MAL-2026-5141 , https://www.bleepingcomputer.com/news/security/red-hat-npm-packages-compromised-to-steal-developer-credentials |
| sap-npm | SAP related (2026-05) | Not investigated | Could not confirm | — |
| nx-console | Malicious version | 18.95.0 (2026-05-18), CVE-2026-48027, listed in KEV, fixed version 18.100.0 | Match (version missing from the specification) | https://nx.dev/blog/nx-console-v18-95-0-postmortem , https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised |
| ovhcloud-cli | 2026-10-19 release / via GlassWorm | Release binaries of v0.11.0–v0.15.0 were replaced on 2026-10-19. The safe version is v0.16.0. The entry point was a compromised developer GitHub account. The link to GlassWorm is a researcher's hypothesis; OVHcloud does not mention it | Differs (attribution not settled) | https://www.helpnetsecurity.com/2026/10/21/ovhcloud-cli-github-malware/ , https://www.securityweek.com/hijacked-developer-account-used-to-plant-stealer-in-ovhcloud-cli/ |
| typosquat-payment-sdk | Payment SDK typosquats (2026-06 to 07) | Not investigated | Could not confirm | — |

## 2. `worm_iocs`

| Item | Specification value | Primary-source value | Verdict | Source URL |
|---|---|---|---|---|
| chaindrop.files | setup.mjs / Math_Symbol.js | The same 2 files (dropper and second stage) | Match | https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/ |
| chaindrop.files | math_init.js | Could not be confirmed | Could not confirm | — |
| chaindrop.preinstall | `node setup.mjs` | Runs setup.mjs from a preinstall hook | Match | https://www.mend.io/blog/keyv-malicious-packages/ |
| setup.mjs sha256 #1 | 54dc7ea5…b350668 | Same value | Match | https://www.mend.io/blog/keyv-malicious-packages/ |
| setup.mjs sha256 #2 | fd3ca400…5684b1eb | No match in the search results | Could not confirm | — |
| Math_Symbol.js sha256 | 9fc2570b…cf1bcc | Same value for Math_Symbol.js. No grounds were found for assigning the same value to math_init.js | Match (could not confirm for math_init.js) | https://www.mend.io/blog/keyv-malicious-packages/ |
| chaindrop C2 | npm-cache[.]com / pypi-get[.]com / js-mirror[.]com | Match. However, the new C2 `awqhnjewqjkl[.]icu` and the resolver contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103` are not in the specification | Differs (missing IoCs) | https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/ , https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/ |
| chaindrop RPC | eth-mainnet.nodereal.io / go.getblock.io / eth.llamarpc.com | Listed as IoCs. However, they are legitimate services, so only connections from unexpected CI runners should be investigated | Match (beware of false positives) | https://op-c.net/blog/chaindrop-npm-supply-chain-attack/ |
| teampcp.c2_ip | 83.142.209.194 / 94.154.172.43 | Both are in the FBI's IoC set | Match | https://www.ic3.gov/CSA/2026/260702.pdf , https://research.jfrog.com/post/shai-hulud-here-we-go-again/ |
| teampcp.c2_domains | api.masscan.cloud / git-tanstack.com | Listed as the campaign's C2 | Match | https://crimson7.io/resources/blogs/teampcp-mini-shai-hulud-supply-chain-campaign/ |
| teampcp.c2_domains | seed1 / seed2.getsession.org | Used to carry stolen data. However, it is legitimate infrastructure of the Session messenger, and blocking at the DNS level is recommended | Match (beware of false positives) | https://phoenix.security/mini-shai-hulud-teampcp-tanstack/ |
| teampcp.urls | https://83.142.209.194/v1/weights , /audio.mp3 | Could not be confirmed | Could not confirm | — |
| teampcp.urls | api.github.com/search/commits?q=FIRESCALE | Could not be confirmed | Could not confirm | — |
| teampcp.oidc_technique | Extract OIDC from `/proc/<pid>/mem` | TanStack's post-incident report says "extracted the OIDC token from the runner's memory" | Match | https://corgea.com/research/tanstack-supply-chain-attack-mini-shai-hulud |
| teampcp.deadman_switch | Wipe all of $HOME when GitHub credentials are revoked | The same behavior is recorded for tensorlake (gh-token-monitor) and Miasma. For TeamPCP itself, JFrog only states that "there is a branch that runs destructive commands" | Differs (attribution unclear) | https://socket.dev/blog/tensorlake-compromise , https://research.jfrog.com/post/shai-hulud-here-we-go-again/ |
| post_shaihulud / IronWorm | Rust stealer malware | Written in Rust. Has an eBPF rootkit and Tor C2, and was planted in 36–37 npm packages (2026-06) | Match | https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/ |
| IronWorm masquerade | cargo-install | On Cargo it uses build-script hooks. Masquerading under the name "cargo-install" could not be confirmed | Could not confirm | https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/ |
| sckit | Written in Go / MemOS, MemoryOS / 2026-09-23 | Match | Match | https://safedep.io/memtensor-sckit-worm-npm-pypi/ |
| miasma.deadman_switch | Delete $HOME on detecting token revocation | Runs `rm -rf ~/` on detecting revocation (up to 72 hours) | Match | https://www.bleepingcomputer.com/news/security/the-miasma-worm-source-code-briefly-leaked-on-github/ |
| miasma.leaked_source | Briefly public on 2026-06-10 | According to The Register it was published on 2026-06-08 (reported 06-09 to 10) | Differs (date) | https://www.theregister.com/cyber-crime/2026/06/09/miasma-supply-chain-attack-toolkit-goes-public-on-github/5253074 |
| Classification of miasma | AI weaponization | It has a feature that poisons AI coding tool settings. No abuse after the leak has been confirmed (McCarthy of Wiz) | Differs (overstated) | Same as above |
| quasar_linux (QLNX) | userland LD_PRELOAD + kernel eBPF | An LD_PRELOAD rootkit using `/etc/ld.so.preload` and an eBPF part that manages BPF maps (sources disagree on whether a kernel-side program exists) | Match | https://labs.cloudsecurityalliance.org/research/csa-research-note-quasar-linux-rat-supply-chain-20260509/ |
| quasar_linux.persistence | systemd / crontab / init.d / XDG / .bashrc | Not checked item by item | Could not confirm | — |
| linkpro | eBPF + LD_PRELOAD fallback | Switches to `/etc/ld.so.preload` (`/etc/libld.so`) when the eBPF Hide module cannot be used. Reported 2025-10 (Synacktiv) | Match | https://thehackernews.com/2025/10/linkpro-linux-rootkit-uses-ebpf-to-hide.html |
| voidlink | LD_PRELOAD / LKM / eBPF | Match (Check Point 2026-01, Elastic's analysis) | Match | https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/ , https://www.elastic.co/security-labs/illuminating-voidlink |

## 3. `infrastructures[]`

| Item | Specification value | Primary-source value | Verdict | Source URL |
|---|---|---|---|---|
| GitLab CVE-2026-110264 | 10.0 / unauthenticated RCE | 10.0, fixed 2026-10-21 (7 release lines from 18.11.13 to 19.5.1), not in KEV as of 10-22 | Match (fixed versions missing from the specification) | https://thehackernews.com/2026/10/critical-gitlab-flaw-cvss-100-could.html , https://securityonline.info/gitlab-critical-patch-release-cve-2026-110264/ |
| GitLab CVE-2026-85706 | 10.0 / path traversal | 10.0, unauthenticated arbitrary file read through the commits API. Fixed versions 19.1.8 / 19.2.6 / 19.3.2, added to KEV on 2026-09-11 | Match | https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild/ |
| GitLab CVE-2026-19478 | 9.4 / GraphQL code injection | There is mention of exploitation through GraphQL code injection. CVSS 9.4 and the affected versions could not be confirmed | Could not confirm | https://www.securityweek.com/gitlab-vulnerability-exploited-one-day-after-disclosure/ |
| TeamCity CVE-2026-63077 | 9.8 / <2026.1.3, <2025.11.7 / KEV due 2026-08-08 | 9.8, fixed versions 2025.11.7 / 2026.1.3, added to KEV on 2026-08-05 with due date 2026-08-08 | Match | https://www.rapid7.com/blog/post/etr-cve-2026-63077-critical-unauthenticated-remote-code-execution-in-jetbrains-teamcity/ , https://kev.5sn.com/2026/CVE-2026-63077 |
| Artifactory CVE-2026-82329 | 9.8 / fixed versions for 6 release lines | 9.8, fixed versions 7.111.21 / 7.117.28 / 7.125.20 / 7.133.29 / 7.146.38 / 7.161.20. JFrog's wording is ambiguous about whether 7.111.21 is included in the boundary | Match | https://docs.jfrog.com/releases/docs/jfrog-security-advisories , https://bishopfox.com/blog/cve-2026-82329-unauthenticated-administrative-access-in-jfrog-artifactory-via-an-empty-cluster-join-key |
| Docker CVE-2026-17106 | CopyEscape (docker cp) | `docker cp` can write arbitrary files on the host (Imperva). The only confirmed fix is `sbx cp` in Docker Sandboxes 0.38.0; no fixed version on the Docker CLI side was found | Match (fixed version could not be confirmed) | https://www.imperva.com/blog/copyescape-taking-over-docker-hosts-with-docker-cp/ |
| Kernel CVE-2026-31431 | Copy Fail / CISA KEV | Added to KEV on 2026-05-01 (due 05-15). Fixed versions 6.18.22 / 6.19.12 / 7.0 | Match | https://threatprotect.qualys.com/2026/05/04/linux-kernel-vulnerability-exploited-in-the-wild-copy-fail-cve-2026-31431/ |
| Kernel CVE-2026-80521 | AF_UNIX UAF / container to host root / 7.8 | 7.8, a GC race in SCM_RIGHTS. Fixed versions 6.12.111 / 6.18.53 / 7.1.10 / 7.2 (secondary source) | Match | https://www.yorku.ca/uit/2026/09/linux-kernel-container-escape-vulnerability-cve-2026-80521/ |
| Kernel CVE-2026-64564 | SCTPhantom / SCTP UAF / "escape succeeded 6/8 times" | ASCONF UAF (Tencent Zhuque Lab, 2026-08-06). Fixed versions 6.6.148 / 6.12.101 / 6.18.42 / 7.1.6. The "6/8" success rate could not be confirmed | Differs (no corroboration for the success rate) | https://matrix.tencent.com/en/2026/08/06/sctphantom-CVE-2026-64564 , https://blog.cloudlinux.com/sctphantom-cve-2026-64564-local-root-exploit-status-and-fixes-for-cloudlinux/ |
| Sigstore CVE-2026-22772 | Fulcio metaRegex SSRF / <1.8.5 | Match (GHSA-59jp-pj84-45mr) | Match | https://nvd.nist.gov/vuln/detail/cve-2026-22772 |
| Sigstore CVE-2026-22703 | Rekor accepts arbitrary entries / <2.6.2, <3.0.4 | The affected product is **Cosign**. Verification passes even for a bundle containing a Rekor entry that does not refer to the artifact. The version ranges match | Differs (product name) | https://osv.dev/CVE-2026-22703 , https://advisories.gitlab.com/pkg/golang/github.com/sigstore/cosign/v2/CVE-2026-22703/ |
| Sigstore CVE-2026-39395 | False positive in verify-blob-attestation / fixed 3.0.6, 2.6.3 | Match (GHSA-w6c6-c85g-mmv6, 4.3) | Match | https://nvd.nist.gov/vuln/detail/CVE-2026-39395 |
| Sigstore GHSA-fx35-mq7g-6g98 | Legacy bundle verification bypass / fixed 3.1.3 | A legacy bundle verification bypass using a public key. The backport to v2.6.5 was confirmed, but "3.1.3" could not be confirmed | Differs (insufficient corroboration of the fixed version) | https://newreleases.io/project/github/sigstore/cosign/release/v2.6.5 |
| Sigstore CVE-2026-31830 | sigstore-ruby / <0.2.3 | Match (GHSA-mhg6-2q2v-9h2c, 7.5) | Match | https://nvd.nist.gov/vuln/detail/CVE-2026-31830 |

## 4. `mcp_poisoning` / `ai_coding_assistant`

| Item | Specification value | Primary-source value | Verdict | Source URL |
|---|---|---|---|---|
| SymJack | Targeted configuration files / `ln -s ../.claude/settings.json docs/vid-settings.mp4` | Disclosed by Adversa AI on 2026-05-26. Detection rule ATR-2026-00572 has the same example. No CVE assigned | Match | https://adversa.ai/blog/the-approval-prompt-is-lying-to-you-symlink-rce-in-five-ai-coding-agents-claude-code-cursor-antigravity-copilot-grok-build/ , https://agentthreatrule.org/zh/rules/ATR-2026-00572 |
| SymJack mitigation | Claude Code v2.1.129+ | A secondary source says "partially fixed in v2.1.129" | Match (secondary source, partial fix) | http://sdd.sh/2026/06/symjack-trustfall-rce-ai-coding-agents/ |
| Deadbugz | Normal for the first 3 calls, malicious from the 4th onward | From the 3rd tools/call onward, the responses to tools/list and prompts/get are altered (Pillar) | Match | https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign |
| NeighborJack | Indirect compromise via an adjacent vulnerable MCP / detect registration of internal IPs | Backslash (2025-06): a misconfiguration where an MCP server binds to 0.0.0.0 and is reachable from the LAN | Differs (definition, detection target) | https://www.csoonline.com/article/4012712/misconfigured-mcp-servers-expose-ai-agent-systems-to-compromise.html |
| SPECTER MCP-POISON | Registry-poisoning tool | Nothing matching was found | Could not confirm | — |
| CVE-2026-52869 | MCP registry supply chain / 7.6 | A flaw in the MCP Python SDK where the session ID is not bound to the authenticated principal. CVSS 7.1, fixed version 1.27.2 (GHSA-jpw9-pfvf-9f58) | Differs (content and CVSS) | https://osv.dev/CVE-2026-52869 , https://advisories.gitlab.com/pypi/mcp/CVE-2026-52869/ |
| CVE-2026-58500 | XSS to RCE in MCP Appium | XSS in the locator UI of appium-mcp, 8.2, fixed version 1.85.10 (GHSA-x975-rgx4-5fh4). Not described as RCE | Differs (the RCE wording) | https://osv.dev/vulnerability/CVE-2026-58500 |
| CVE-2026-104850 | OAuth spoofing in the MCP TS SDK | 7.5, fixed versions 1.31.0 / 2.2.0 (GHSA-6qxp-vccf-f47h) | Match | https://advisories.gitlab.com/npm/@modelcontextprotocol/sdk/CVE-2026-104850/ |
| CVE-2026-104120 | fetch_url in mcp-server-fetch / everything | SSRF (≤2026.6.4), no fixed version yet | Match | https://app.opencve.io/cve/CVE-2026-104120 |
| CVE-2026-111767 | Broken access control in InMemoryTaskStore | A flaw of the same kind is WS-2026-0090 (@modelcontextprotocol/sdk 1.24.0–1.31.0, fixed version 1.32.0). The mapping to the CVE number could not be confirmed | Could not confirm | https://mend.io/vulnerability-database/WS-2026-0090/ |
| CVE-2026-59951 | Session accumulation in FastMCP | Sessions accumulate without limit in the Streamable HTTP of the MCP Python SDK. Fixed versions 1.30.0 / 2.2.0 | Match | https://osv.dev/vulnerability/CVE-2026-59951 |
| CVE-2026-61559 | Server-side flaw in gitlab-mcp | An SSRF in @zereight/mcp-gitlab leaks the token. 9.6, fixed version 2.1.27 | Match | https://osv.dev/vulnerability/CVE-2026-61559 |
| ToolHive GO-2026-5996 | Missed IPv6 NAT64 ranges | CVE-2026-54450. Misses 64:ff9b::/96 and 64:ff9b:1::/48 | Match | https://osv.dev/vulnerability/GO-2026-5996 |
| ToolHive GO-2026-6002 | NAT64 / host.docker.internal | GO-2026-6002 is an SSRF in the auth discovery path (CVE-2026-58196). Lateral movement through host.docker.internal is a separate CVE, CVE-2026-58197 | Differs (mixed up) | https://advisories.gitlab.com/pkg/golang/github.com/stacklok/toolhive/ |
| Cursor CVE-2026-26268 | 9.9 / fixed in 2.5 | 9.9 in NVD, 8.0 from GitHub (CNA). A sandbox escape by writing to .git configuration and hooks, fixed in 2.5 | Match | https://nvd.nist.gov/vuln/detail/CVE-2026-26268 |
| Cursor CVE-2026-50548 | Zero-Click prompt injection ("<2.5" in §41) | DuneSlide. 9.8, path traversal through the working_directory of `run_terminal_cmd`. **The fixed version is Cursor 3.0** | Differs (fixed version) | https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html , https://www.catonetworks.com/blog/duneslide-two-critical-rce-vulnerabilities |
| EUVD-2026-39537 | Alias of CVE-2026-50548 | The mapping could not be confirmed | Could not confirm | — |
| Cursor CVE-2025-54136 | Zero-Click configuration RCE through MCP JSON | MCPoison. 7.2, fixed in 1.3 | Match | https://blog.checkpoint.com/research/cursor-ide-persistent-code-execution-via-mcp-trust-bypass/ |
| Cursor git.exe 0-day | Unfixed / automatically runs git.exe in the repository root | Disclosed by Mindgard on 2026-07-14 (unfixed up to 3.2.16). The same behavior has been reported in Copilot CLI / Gemini CLI / Codex | Match | https://www.securityweek.com/unpatched-cursor-vulnerability-exposes-users-to-code-execution/ |
| Copilot CVE-2025-62222 | Command execution before the trust dialog is shown | Command injection in the VS Code Copilot Chat extension (8.8, fixed version 0.32.5). Execution "before the trust dialog is shown" could not be confirmed | Differs (description) | https://osv.dev/vulnerability/CVE-2025-62222 |
| Copilot CVE-2026-50510 | Local code execution in the JetBrains version | 7.8, <1.13.0 (CWE-641) | Match | https://app.opencve.io/cve/CVE-2026-50510 |

## 5. `github_actions` / `browser_extensions`

| Item | Specification value | Primary-source value | Verdict | Source URL |
|---|---|---|---|---|
| trivy-action | v0.69.4 (75 of 76 tags poisoned, 2026-03) | On 2026-03-19, tags 75/76 of trivy-action were force-pushed (76/77 according to Aqua's announcement). **v0.69.4 is the malicious version of the Trivy binary**. The safe versions are trivy-action v0.35.0 / trivy v0.69.3 | Differs (what the version number refers to) | https://snyk.io/articles/trivy-github-actions-supply-chain-compromise/ , https://thehackernews.com/2026/03/trivy-security-scanner-github-actions.html |
| megalodon | 5,561 repositories / 2026-05 | Match (2026-05-18) | Match | https://labs.cloudsecurityalliance.org/research/csa-research-note-megalodon-github-actions-cicd-supply-chain |
| mass_workflow_planting / GhostAction | 500+ accounts / from 2026-10-07 | Socket: from 2026-10-07 to 09, 500+ accounts committed workflows disguised as a "security audit" | Match | https://breached.company/ghostaction-returns-malicious-github-actions-workflow-hits-500-accounts-tens/ |
| mass_workflow_planting.stolen_secrets | PyPI / npm / DockerHub | Could not be checked | Could not confirm | — |
| ghostaction fake font | An infostealer hidden in a fake font, plus a second workflow | The fake font (`public/fonts/fa-solid-400.woff2`, 94 repositories, launched by folderOpen in tasks.json) is reported as **a separate follow-up / copycat activity**, distinct from the 500-account wave | Differs (two incidents mixed up) | https://thehackernews.com/2026/10/ghostaction-attackers-plant-credential.html , https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file |
| 19 Chrome/Edge extensions (ownership transfer) | 2026 | The figure "19" could not be confirmed | Could not confirm | — |
| Save Image as Type | 1M+ users, affiliate fraud | Match (acquired by Karma in 2025-11) | Match | https://www.techspot.com/news/111737-popular-chrome-extension-save-image-type-hijacked-impacting.html |
| QuickLens | About 7,000 users | Match (malicious update on 2026-02-17) | Match | https://cyberwarzone.com/2026/03/16/chrome-extensions-turned-malicious-after-ownership-transfer-pushing-code-injection-and-fake-updates/ |
| ShotBird | About 800 users | Match | Match | Same as above |
| GlassWorm | WebSocket RAT | Not investigated | Could not confirm | — |
| ModHeader | Dormant stealing code in a signed legitimate extension | Dormant code in 7.0.18. About 1.6 million installs, removed from the store in 2026-07. Extension ID idgpnmonknjnojddfkpgkljpfnnfcklj | Match (ID missing from the specification) | https://vpncentral.com/modheader-extension-with-1-6-million-installs-contained-dormant-data-exfiltration-code/ |

## 6. Other (§6 / markers / process_signatures)

| Item | Specification value | Primary-source value | Verdict | Source URL |
|---|---|---|---|---|
| eMudhra test host | dv-g3b-emudhra.we-have-a-problem.com (connection succeeds = CRITICAL, SSL error = SAFE) | The official test page has this host name (and also dv-g3b-aaa-emudhra). "A certificate error = you do not trust the compromised intermediate CA" | Match | https://emudhra.we-have-a-problem.com/ |
| Timing of the eMudhra incident | — | Reported to Mozilla on 2026-10-17; the private keys of 8 intermediate CAs leaked | Match (reference) | https://bugzilla.mozilla.org/show_bug.cgi?id=2083449 |
| Homebrew ca-certificates | 2026-09-25_1+ | Dated before the incident (10-17), which is contradictory for a fixed version. Not corroborated | Could not confirm (suspected error) | — |
| Go 1.27.3 / 1.26.10 | Versions addressing eMudhra | Could not be confirmed | Could not confirm | — |
| marker | /tmp/remote_code_loader.lock | Listed as an IoC of litellm 1.107.0 | Match | https://www.mend.io/blog/litellm-1-107-0-compromised/ |
| process_signatures | litellm.dev | Sends to the fake domain `www.litellm.dev` | Match | https://www.upwind.io/feed/litellm-1-107-0-supply-chain-attack-malicious-code-found-in-pypi-package |

---

## Items that could not be confirmed

(Related rows are grouped, so this does not correspond one-to-one with the 23 "Could not confirm" rows in the tables)

1. Malicious file names of @tanstack/* (router_init.js / tanstack_runner.js / vite_setup.mjs)
2. @asyncapi/* (not investigated)
3. @polymarket/* (not investigated)
4. Individual versions of cacheable 2.5.1 / @cacheable/memory 2.2.1 / @cacheable/node-cache 3.1.2 / @cacheable/utils 2.5.1 / @cacheable/net 2.1.1
5. py2ops 2.2 (sources contradict each other)
6. @solana-labs/spl-toke / web3-js / ancor
7. sap-npm (not investigated)
8. typosquat-payment-sdk (not investigated)
9. math_init.js of chaindrop
10. The second hash of setup.mjs, fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb
11. teampcp URLs (/v1/weights, /audio.mp3, FIRESCALE)
12. IronWorm's cargo-install masquerade
13. Individual items of QLNX's persistence techniques
14. CVSS 9.4 and affected versions of GitLab CVE-2026-19478
15. SPECTER MCP-POISON
16. CVE-2026-111767 (whether it is the same as WS-2026-0090)
17. EUVD-2026-39537
18. What GhostAction stole (PyPI / npm / DockerHub)
19. 19 Chrome/Edge extensions (ownership transfer)
20. GlassWorm (not investigated)
21. Homebrew ca-certificates 2026-09-25_1
22. Go 1.27.3 / 1.26.10

**Not investigated**: the technique descriptions in §3.6–§3.12 that contain no CVE or campaign name (`dangerous_patterns`, `build_hooks`, `persistence`, the general techniques in `anti_forensics`), the rest of `process_signatures` (letters9813 / pythonclient-test / PRIVCOLLECT / npm-cache / math_init), `/tmp/.pc_once_*` in `markers`, Djinn / OmniStealer in §9.4, and Python 3.15.1 / 3.14.9 / 3.13.17 in §5.

---

## Applied in 5.2.1 (2026-10-22)

Based on the user's approval, the differences confirmed by primary sources were applied to `rules/ioc.json` and `zes-scan.sh`. Values that could not be confirmed (the "Could not confirm" rows) were not changed; notes were added where needed.

| Item | Change | Basis (row of this report) |
|---|---|---|
| certifi | campaign `litellm-oct2026` → `emudhra-ca-oct2026`; range set to `>=2019.3.9 <2026.10.19` | certifi row (GHSA-6q48-6c7w-9gw2) |
| intercom-client | Set compromised version 7.0.4 and safe version 7.0.3; removed the "1,800+" statement | intercom-client row (GHSA-54pg-9963-v8vg) |
| jscrambler | Limited malicious versions to 8.14.0 / 8.16.0 / 8.17.0 / 8.18.0 / 8.20.0, safe version 8.22.0, split the campaign into `jscrambler-jul2026` (TeamPCP attribution not confirmed) | jscrambler row |
| lightning / telnyx | Values kept. Added notes on the publication dates (04-30 / 03-27) and GHSA | Each row |
| css-nesting-transform | Added notes on MAL-2026-17804 and the publication date 10-07 | Same row |
| lerobot | Set affected range `<=0.5.1` (CRITICAL). Added a note on the CVSS inconsistency between sources | lerobot row |
| ovhcloud-cli | Affected v0.11.0–v0.15.0, safe version v0.16.0. Noted that the GlassWorm attribution is not settled | ovhcloud-cli row |
| ChainDrop | Added C2 `awqhnjewqjkl[.]icu` and resolver contract `0xE1f2…3103`. Moved the 3 Ethereum RPC hosts to `legit_infra` (MEDIUM) | chaindrop C2 / RPC rows |
| TeamPCP | Moved `seed1/seed2.getsession.org` to `legit_infra` (MEDIUM). Noted that the attribution of deadman_switch is unclear | teampcp rows |
| Miasma | Publication date 06-08; corrected the "AI weaponization" wording | Miasma rows |
| GitLab CVE-2026-85706 | Set fixed versions 19.1.8 / 19.2.6 / 19.3.2 (CRITICAL in §3). For 110264 only a note, because per-line fixed versions are not confirmed | GitLab rows |
| Kernel | Set fixed versions for Copy Fail / CVE-2026-80521 / SCTPhantom (HIGH in §23). Removed the "6/8" statement | Kernel rows |
| Docker CVE-2026-17106 | Noted that the CLI fixed version is not confirmed | Docker row |
| CVE-2026-22703 | Corrected the affected product to Cosign. Removed the Rekor image check from §43 | Sigstore row |
| GHSA-fx35-mq7g-6g98 | Added the 2.x fixed version 2.6.5 (noted that 3.1.3 is not confirmed) | Same row |
| NeighborJack | Corrected the definition to "listening on 0.0.0.0" (§20 still detects both, as before) | NeighborJack row |
| CVE-2026-52869 / 58500 | Moved to mcp_cves; `mcp<1.27.2` / `appium-mcp<1.85.10` rated HIGH in §37 | Each row |
| ToolHive | Corrected the mix-up between GO-2026-6002 and CVE-2026-58197 | ToolHive rows |
| Cursor CVE-2026-50548 | Set fixed version 3.0 (<3.0 is CRITICAL in §41) | Cursor row |
| Copilot CVE-2025-62222 | Copilot Chat extension <0.32.5 rated HIGH in §41; corrected the description | Copilot row |
| trivy-action | Corrected v0.69.4 to be the version of Trivy itself. For trivy-action, tag references other than v0.35.0 are CRITICAL, and pinning Trivy itself to v0.69.4 is CRITICAL | trivy-action row |
| GhostAction | Noted that the fake-font incident is a separate case | ghostaction row |
| Homebrew ca-certificates | Because the reference value is suspected to be wrong, changed the rating from HIGH → MEDIUM (needs confirmation) | Homebrew row |

`incident_bundle` stays `ZES-2026-OCT-EMERGENCY-V5.2` (to keep the findings.json schema format `V<major>.<minor>`).

## Intelligence added in 5.2.2 (2026-10-22)

Threat information published from 2026-06 to 10 was collected from the primary sources of each vendor and research organization (NVD / CISA KEV / GHSA / OSV / vendor advisories and research blogs) and imported into `packages[]`, `infrastructures[]` and `intel` in `rules/ioc.json`. Entries whose `verification` is `secondary` could not be traced to a primary source and were filled in from secondary reporting (they are detected, but the values are less certain than primary-source values).

Import policy:

- **Suppressing false positives:** generic file names (`index.js`, `build.rs`, `settings.json`, etc.), generic strings, and domains of legitimate services on their own (github.com, api.telegram.org, etc.) are not used for matching. Specific URLs on legitimate services are treated as `legit_infra` (MEDIUM).
- **Severity:** malicious packages are CRITICAL; vulnerable versions (not malicious, but within a CVE's affected range) are HIGH with `match: vulnerable_versions`. Version checks of local tools are capped at HIGH to allow for distribution backports.
- **Not supported (cannot be determined statically):** GitHub Enterprise Server, Tekton Pipelines-as-Code, Docker Sandboxes, 7-Zip, Git for Windows (the version cannot be taken from the image name or binary, or Windows only), sudo CVE-2026-82474 (fixed version unknown), the Jenkins Script Security plugin (no way to get the plugin version), and Kiro for Windows. They are recorded as data.

### Packages (41 entries)

| Published | Target | Severity | Confidence | Primary source |
|---|---|---|---|---|
| 2026-06-06 | hades-pypi-pth-jun2026 | HIGH | confirmed | https://orca.security/resources/blog/hades-pypi-supply-chain-attack/ |
| 2026-06-06 | hades-pypi-pth-jun2026 | HIGH | confirmed | https://orca.security/resources/blog/hades-pypi-supply-chain-attack/ |
| 2026-06-06 | hades-pypi-pth-jun2026 | HIGH | confirmed | https://orca.security/resources/blog/hades-pypi-supply-chain-attack/ |
| 2026-06-17 | mastra-easy-day-js-jun2026 | CRITICAL | confirmed | https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js |
| 2026-06-17 | mastra-easy-day-js-jun2026 | CRITICAL | confirmed | https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js |
| 2026-06-17 | mastra-easy-day-js-jun2026 | CRITICAL | confirmed | https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js |
| 2026-06-24 | leo-platform-phantom-gyp-jun2026 | HIGH | confirmed | https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised |
| 2026-06-24 | leo-platform-phantom-gyp-jun2026 | HIGH | confirmed | https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised |
| 2026-06-24 | leo-platform-phantom-gyp-jun2026 | HIGH | confirmed | https://www.stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised |
| 2026-07-19 | sleepergem-rubygems-jul2026 | HIGH | confirmed | https://www.stepsecurity.io/blog/sleepergem-compromised-rubygems-drop-persistent-backdoor |
| 2026-07-19 | sleepergem-rubygems-jul2026 | HIGH | confirmed | https://www.stepsecurity.io/blog/sleepergem-compromised-rubygems-drop-persistent-backdoor |
| 2026-07-19 | sleepergem-rubygems-jul2026 | HIGH | confirmed | https://www.stepsecurity.io/blog/sleepergem-compromised-rubygems-drop-persistent-backdoor |
| 2026-07-24 | mrmustard-pth-stealer-jul2026 | HIGH | confirmed | https://www.stepsecurity.io/blog/compromised-pypi-mrmustard-0-7-4-credential-stealer |
| 2026-07-28 | joyfill-import-rat-jul2026 | HIGH | confirmed | https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise |
| 2026-07-28 | joyfill-import-rat-jul2026 | HIGH | confirmed | https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise |
| 2026-07-28 | alibaba-aone-rat-jul2026 | HIGH | confirmed | https://socket.dev/blog/npm-rat-targets-alibaba |
| 2026-07-28 | alibaba-aone-rat-jul2026 | HIGH | confirmed | https://socket.dev/blog/npm-rat-targets-alibaba |
| 2026-08-04 | chaindrop-shai-hulud-aug2026 | CRITICAL | confirmed | https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/ |
| 2026-08-04 | chaindrop-shai-hulud-aug2026 | CRITICAL | confirmed | https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/ |
| 2026-08-16 | stubmaker-rubygems-aug2026 | HIGH | confirmed | https://opensourcemalware.com/blog/stubmaker-rubygems-windows-infostealer |
| 2026-08-16 | stubmaker-rubygems-aug2026 | HIGH | confirmed | https://opensourcemalware.com/blog/stubmaker-rubygems-windows-infostealer |
| 2026-08-20 | proc-macro1-rust-dropper-aug2026 | CRITICAL | confirmed | https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack |
| 2026-08-20 | proc-macro1-rust-dropper-aug2026 | CRITICAL | confirmed | https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack |
| 2026-08-20 | proc-macro1-rust-dropper-aug2026 | CRITICAL | confirmed | https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack |
| 2026-08-20 | proc-macro1-rust-dropper-aug2026 | CRITICAL | confirmed | https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack |
| 2026-08-28 | shai-hulud-trinitite-aug2026 | CRITICAL | confirmed | https://socket.dev/blog/openapi-react-query-codegen-npm-compromise |
| 2026-09-07 | shai-hulud-resurface-sep2026 | HIGH | confirmed | https://www.aikido.dev/blog/shai-hulud-npm-resurfaces |
| 2026-09-07 | shai-hulud-resurface-sep2026 | HIGH | confirmed | https://www.aikido.dev/blog/shai-hulud-npm-resurfaces |
| 2026-09-17 | polinrider-packagist-sep2026 | HIGH | confirmed | https://socket.dev/blog/polinrider-github-packagist |
| 2026-09-22 | graphalgo-go-terraform-sep2026 | HIGH | confirmed | https://www.aikido.dev/blog/graphalgo-terraform-go-modules |
| 2026-09-22 | graphalgo-go-terraform-sep2026 | HIGH | confirmed | https://www.aikido.dev/blog/graphalgo-terraform-go-modules |
| 2026-09-23 | sckit-supplychain-local-worm-sep2026 | HIGH | confirmed | https://semgrep.dev/blog/2026/the-ai-ecosystem-has-worms-now-inside-the-memtensor-compromise |
| 2026-09-23 | sckit-supplychain-local-worm-sep2026 | HIGH | confirmed | https://semgrep.dev/blog/2026/the-ai-ecosystem-has-worms-now-inside-the-memtensor-compromise |
| 2026-10-04 | anthropic-sdk-typosquat-oct2026 | HIGH | confirmed | https://osv.dev/vulnerability/MAL-2026-17472 |
| 2026-10-05 | subql-ci-artifact-backdoor-oct2026 | HIGH | confirmed | https://www.stepsecurity.io/blog/subql-ecosystem-compromised |
| 2026-10-05 | rubygems-crypto-extconf-oct2026 | MEDIUM | confirmed | https://osv.dev/vulnerability/MAL-2026-17583 |
| 2026-10-12 | apex-accelerator-ref8801-oct2026 | HIGH | confirmed | https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages |
| 2026-10-12 | apex-accelerator-ref8801-oct2026 | HIGH | confirmed | https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages |
| 2026-10-20 | semver-typosquat-pypi-oct2026 | MEDIUM | confirmed | https://osv.dev/vulnerability/MAL-2026-18103 |
| 2026-10-21 | litellm-pth-stealer-oct2026 | CRITICAL | confirmed | https://docs.litellm.ai/blog/security-incident-oct-21-2026 |
| 2026-10-21 | litellm-pth-stealer-oct2026 | CRITICAL | confirmed | https://docs.litellm.ai/blog/security-incident-oct-21-2026 |

### CI/CD (24 entries)

| Published | Target | Severity | Confidence | Primary source |
|---|---|---|---|---|
| 2026-06-01 | redhat-miasma-oidc-jun2026 | CRITICAL | confirmed | https://www.aikido.dev/blog/red-hat-npm-packages-compromised-credential-stealing-worm |
| 2026-06-01 | claude-code-action-issue-injection-jun2026 | HIGH | confirmed | https://flatt.tech/research/posts/poisoning-claude-code-one-github-issue-to-break-the-supply-chain/ |
| 2026-06-05 | azure-durabletask-miasma-jun2026 | HIGH | confirmed | https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents |
| 2026-06-08 | hades-pypi-runner-memory-jun2026 | CRITICAL | confirmed | https://stepsecurity.io/blog/the-hades-campaign-pypi-packages |
| 2026-06-18 | checkout-v7-pwn-request-guard-jun2026 | HIGH | confirmed | https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout/ |
| 2026-06-24 | codfish-semantic-release-action-jun2026 | CRITICAL | confirmed | https://www.stepsecurity.io/blog/supply-chain-compromise-codfish-semantic-release-action |
| 2026-06-24 | mawesome-action-jun2026 | HIGH | confirmed | https://www.stepsecurity.io/blog/simonecorsi-mawesome-github-action-has-been-compromised |
| 2026-06-25 | leo-platform-phantom-gyp-jun2026 | CRITICAL | confirmed | https://stepsecurity.io/blog/mass-npm-supply-chain-attack-20-leo-platform-packages-compromised |
| 2026-07-14 | asyncapi-miasma-jul2026 | CRITICAL | confirmed | https://www.wiz.io/blog/m-red-team-asyncapi-supply-chain-compromise-via-github-actions |
| 2026-07-16 | claude-code-action-mcp-json-jul2026 | HIGH | confirmed | https://osv.dev/vulnerability/CVE-2026-47751 |
| 2026-07-22 | cpanel-actions-abuse-jul2026 | HIGH | confirmed | https://socket.dev/blog/github-actions-abuse-powers-cpanel-and-whm-exploitation |
| 2026-08-04 | chaindrop-worm-aug2026 | CRITICAL | confirmed | https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/ |
| 2026-08-28 | trinitite-7nohe-issue-comment-aug2026 | CRITICAL | confirmed | https://www.stepsecurity.io/blog/7nohe-openapi-react-query-codegen-compromised-npm-publishing-workflow |
| 2026-09-10 | actions-cache-readonly-and-cache-mode-2026 | HIGH | confirmed | https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers/ |
| 2026-09-11 | gitlab-cve-2026-85706-sep2026 | CRITICAL | secondary | https://www.wiz.io/vulnerability-database/cve/cve-2026-85706 |
| 2026-09-17 | workflow-execution-protections-sep2026 | MEDIUM | confirmed | https://github.blog/changelog/2026-09-17-workflow-execution-protections-in-github-actions-generally-available/ |
| 2026-09-23 | gitlab-incoming-email-token-sep2026 | HIGH | confirmed | https://www.aikido.dev/blog/gitlab-email-push-to-main |
| 2026-09-23 | memtensor-sckit-sep2026 | HIGH | confirmed | https://www.aikido.dev/blog/supplychain-local-memtensor-npm-pypi |
| 2026-09-24 | actions-cool-reactivation-sep2026 | CRITICAL | confirmed | https://socket.dev/blog/mini-shai-hulud-actions |
| 2026-09-24 | actions-cool-reactivation-sep2026 | CRITICAL | confirmed | https://www.stepsecurity.io/blog/actions-cool-issues-helper-github-action-compromised-all-tags-point-to-imposter-commit-that-exfiltrates-ci-cd-credentials |
| 2026-10-05 | subql-publish-workflow-oct2026 | CRITICAL | confirmed | https://www.stepsecurity.io/blog/subql-ecosystem-compromised |
| 2026-10-08 | tensorlake-hostage-token-oct2026 | CRITICAL | confirmed | https://stepsecurity.io/blog/tensorlake-npm-compromised-hostage-token-worm |
| 2026-10-09 | ghostaction-security-audit-wave-2026 | CRITICAL | confirmed | https://www.stepsecurity.io/blog/ghostaction-returns |
| 2026-10-21 | litellm-release-lookalike-oct2026 | CRITICAL | confirmed | https://docs.litellm.ai/blog/security-incident-oct-21-2026 |

### Development infrastructure and runtime CVEs (47 entries)

| Published | Target | Severity | Confidence | Primary source |
|---|---|---|---|---|
| 2022-03-03 | linux-kernel CVE-2022-0492 | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2022-0492 |
| 2026-06-09 | openssl CVE-2026-45447 | HIGH | confirmed | https://openssl-library.org/news/secadv/20260609.txt |
| 2026-06-10 | jenkins CVE-2026-53435 | HIGH | confirmed | https://www.jenkins.io/security/advisory/2026-06-10/ |
| 2026-06-19 | containerd CVE-2026-53488 | CRITICAL | confirmed | https://github.com/containerd/containerd/security/advisories/GHSA-xhf5-7wjv-pqxp |
| 2026-06-23 | cpython CVE-2026-11940 | HIGH | confirmed | https://github.com/python/cpython/issues/151558 |
| 2026-06-25 | linux-kernel CVE-2026-53266 | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-53266 |
| 2026-06-26 | kestra CVE-2026-49869 | CRITICAL | confirmed | https://github.com/kestra-io/kestra/security/advisories/GHSA-5vc5-wxxq-3fjx |
| 2026-06-30 | sigstore-fulcio CVE-2026-49478 | HIGH | confirmed | https://github.com/sigstore/fulcio/security/advisories/GHSA-f5mr-q85p-6hh6 |
| 2026-07-01 | sigstore-js CVE-2026-48815 | HIGH | confirmed | https://github.com/sigstore/sigstore-js/security/advisories/GHSA-52v5-jr5w-gjxr |
| 2026-07-03 | gitea CVE-2026-20896 | CRITICAL | confirmed | https://github.com/go-gitea/gitea/security/advisories/GHSA-f75j-4cw6-rmx4 |
| 2026-07-04 | linux-kernel CVE-2026-53362 | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-53362 |
| 2026-07-08 | openssh CVE-2026-60002 | CRITICAL | confirmed | https://www.openssh.org/releasenotes.html |
| 2026-07-21 | buildkit CVE-2026-15793 | HIGH | confirmed | https://github.com/moby/buildkit/security/advisories/GHSA-hw3h-2gp9-cxpv |
| 2026-07-21 | openjdk CVE-2026-41254 | HIGH | secondary | https://openjdk.org/groups/vulnerability/advisories/2026-07-21 |
| 2026-07-27 | artifactory CVE-2026-42016 | HIGH | confirmed | https://docs.jfrog.com/releases/docs/jfrog-security-advisories |
| 2026-07-29 | nodejs CVE-2026-56848 | HIGH | confirmed | https://nodejs.org/en/blog/vulnerability/july-2026-security-releases |
| 2026-07-29 | 7-zip CVE-2026-14266 | HIGH | confirmed | https://www.7-zip.org/history.txt |
| 2026-07-30 | php CVE-2026-17543 | CRITICAL | confirmed | https://github.com/php/php-src/security/advisories/GHSA-7qpv-r5mr-78m4 |
| 2026-08-05 | jenkins CVE-2026-70426 | CRITICAL | confirmed | https://www.jenkins.io/security/advisory/2026-08-05/ |
| 2026-08-05 | github-enterprise-server CVE-2026-17556 | CRITICAL | confirmed | https://docs.github.com/en/enterprise-server@3.21/admin/release-notes#3.21.4 |
| 2026-08-07 | nexus-repository CVE-2026-17603 | HIGH | confirmed | https://help.sonatype.com/en/sonatype-nexus-repository-3-95-0-release-notes.html |
| 2026-08-12 | artifactory CVE-2026-42018 | HIGH | confirmed | https://docs.jfrog.com/releases/docs/jfrog-security-advisories |
| 2026-08-12 | artifactory CVE-2026-66384 | HIGH | confirmed | https://docs.jfrog.com/releases/docs/jfrog-security-advisories |
| 2026-08-13 | go CVE-2026-56865 | HIGH | confirmed | https://pkg.go.dev/vuln/GO-2026-6179 |
| 2026-08-17 | gitlab CVE-2026-19478 | CRITICAL | confirmed | https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-2-4-released/ |
| 2026-08-18 | docker CVE-2026-17106 | HIGH | confirmed | https://docs.docker.com/security/security-announcements/ |
| 2026-08-21 | git-for-windows CVE-2026-62960 | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-62960 |
| 2026-08-25 | gitea CVE-2026-60004 | CRITICAL | confirmed | https://github.com/go-gitea/gitea/security/advisories/GHSA-rcr6-4jqh-j84m |
| 2026-08-29 | sudo CVE-2026-82474 | HIGH | secondary | https://nvd.nist.gov/vuln/detail/CVE-2026-82474 |
| 2026-09-02 | jenkins CVE-2026-84645 | HIGH | confirmed | https://www.jenkins.io/security/advisory/2026-09-02/ |
| 2026-09-10 | gitlab CVE-2026-85706 | CRITICAL | confirmed | https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-3-2-released/ |
| 2026-09-10 | forgejo CVE-2026-89094 | CRITICAL | confirmed | https://codeberg.org/forgejo/forgejo/milestone/139655 |
| 2026-09-15 | tekton-pipelines-as-code CVE-2026-54167 | HIGH | confirmed | https://github.com/tektoncd/pipelines-as-code/releases/tag/v0.48.0 |
| 2026-09-15 | docker-sandboxes CVE-2026-77179 | CRITICAL | confirmed | https://docs.docker.com/security/security-announcements/ |
| 2026-09-16 | jenkins-plugin-script-security CVE-2026-92123 | HIGH | confirmed | https://www.jenkins.io/security/advisory/2026-09-16/ |
| 2026-09-22 | github-enterprise-server CVE-2026-77987 | CRITICAL | confirmed | https://docs.github.com/en/enterprise-server@3.22/admin/release-notes#3.22.1 |
| 2026-09-29 | openssl CVE-2026-84782 | HIGH | confirmed | https://openssl-library.org/news/secadv/20260929.txt |
| 2026-10-05 | bitbucket CVE-2026-21589 | CRITICAL | confirmed | https://confluence.atlassian.com/security/cve-2026-21589-arbitrary-file-access-vulnerability-impacts-multiple-products-1870495748.html |
| 2026-10-06 | teamcity CVE-2026-106218 | CRITICAL | confirmed | https://www.jetbrains.com/privacy-security/issues-fixed/ |
| 2026-10-07 | openssh CVE-2026-106583 | HIGH | confirmed | https://www.openssh.org/releasenotes.html |
| 2026-10-12 | containerd CVE-2026-95837 | HIGH | confirmed | https://github.com/containerd/containerd/security/advisories/GHSA-p7v4-vr35-mj6f |
| 2026-10-13 | argo-cd CVE-2026-77459 | CRITICAL | confirmed | https://github.com/argoproj/argo-cd/security/advisories/GHSA-fmxq-cgp8-87wp |
| 2026-10-13 | podman CVE-2026-94603 | CRITICAL | confirmed | https://github.com/podman-container-tools/podman/releases/tag/v5.8.8 |
| 2026-10-14 | curl CVE-2026-92392 | HIGH | confirmed | https://curl.se/docs/CVE-2026-92392.html |
| 2026-10-15 | teamcity CVE-2026-111094 | CRITICAL | confirmed | https://www.jetbrains.com/privacy-security/issues-fixed/ |
| 2026-10-21 | gitlab CVE-2026-110264 | CRITICAL | confirmed | https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/ |
| 2026-10-21 | nodejs CVE-2026-111497 | HIGH | confirmed | https://nodejs.org/en/blog/vulnerability/october-2026-security-releases |

### Host (infostealers, persistence) (29 entries)

| Published | Target | Severity | Confidence | Primary source |
|---|---|---|---|---|
| 2026-06-17 | mastra-npm-easy-day-js | CRITICAL | confirmed | https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/ |
| 2026-06-23 | macos-gaslight-flatroof | HIGH | confirmed | https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/ |
| 2026-06-23 | atomic-arch-aur-scales-ebpf | HIGH | confirmed | https://sandflysecurity.com/blog/linux-scales-ebpf-rootkit-detection-and-analysis |
| 2026-07-01 | polinrider-vscode-folderopen-woff2 | HIGH | confirmed | https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands |
| 2026-07-02 | pamstealer-maccy-rust | HIGH | confirmed | https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/ |
| 2026-07-13 | crashstealer-werkbit-fake-meeting-app | HIGH | confirmed | https://www.jamf.com/blog/crashstealer-macos-infostealer-analysis/ |
| 2026-07-14 | asyncapi-npm-compromise | CRITICAL | confirmed | https://securitylabs.datadoghq.com/articles/compromised-asyncapi-npm-packages/ |
| 2026-07-16 | clicklock-stealer-gsocket | HIGH | confirmed | https://www.group-ib.com/blog/clicklock-stealer-macos-malware/ |
| 2026-07-18 | contagious-interview-svg-steganography | HIGH | confirmed | https://www.elastic.co/security-labs/threat-command/contagious-interview-malware-svg-steganography |
| 2026-07-30 | xmrig-pam-rootok-smokescreen | MEDIUM | confirmed | https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/ |
| 2026-07-31 | xcsset-v40-xcode | HIGH | confirmed | https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/ |
| 2026-08-04 | openvsx-evil-twin-mangorbit | MEDIUM | secondary | https://thehackernews.com/2026/08/open-vsx-removes-77-malicious-evil-twin.html |
| 2026-08-05 | ms-macos-clickfix-cloaked-gate | MEDIUM | confirmed | https://www.microsoft.com/en-us/security/blog/2026/08/05/macos-clickfix-campaign-learned-hide/ |
| 2026-08-06 | overlord-fake-zoom-dotnet | HIGH | confirmed | https://www.jamf.com/blog/fake-zoom-installer-delivers-overlord-rat-macos/ |
| 2026-08-13 | amnesiastealer-clickfix-github | CRITICAL | confirmed | https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/ |
| 2026-08-20 | redc2-redshell-npm-streak | CRITICAL | confirmed | https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/redc2-ai-powered-linux-implant |
| 2026-08-20 | arrayref-proc-macro1-rust | CRITICAL | confirmed | https://www.wiz.io/blog/rust-supply-chain-attack-on-arrayref-significant-overlap-with-dprk-campaigns |
| 2026-08-20 | n4d-mesh-controller-go-titan | HIGH | confirmed | https://securitylabs.datadoghq.com/articles/n4d-mesh-controller-go-titan-new-infrastructure-hunting/ |
| 2026-09-01 | mirage-kitten-noderabbit-pollcat | HIGH | confirmed | https://securelist.com/mirage-kitten-new-backdoors-noderabbit-pollcat/121244/ |
| 2026-09-13 | red-heron-gitea-jitterly-sixzut | HIGH | confirmed | https://www.acronis.com/en/tru/posts/red-heron-exploits-gitea-n-day-flaw-in-multinational-campaign-exposing-new-linux-rootkit/ |
| 2026-09-17 | weaselbiscuit-npm-biz44 | MEDIUM | secondary | https://opensourcemalware.com/blog/introducing-weaselbiscuit |
| 2026-09-18 | tradertraitor-terraform-lockfile-flatroof-roofdeck | CRITICAL | confirmed | https://www.sentinelone.com/labs/dont-call-us-well-call-your-apis-tradertraitor-backdoors-resurface-on-victim-with-no-crypto-ties/ |
| 2026-09-22 | pamstealer-wavel-wallet | HIGH | confirmed | https://www.jamf.com/blog/pamstealer-wavel-macos-infostealer/ |
| 2026-09-24 | macsync-icloud-calendar-finder-backdoor | HIGH | confirmed | https://securelist.com/macsync-new-version/121383/ |
| 2026-09-30 | cloudsyncd-fake-zoom | HIGH | confirmed | https://www.jamf.com/blog/cloudsyncd-macos-backdoor-fake-zoom-installer/ |
| 2026-10-12 | apex-accelerator-npm-cloudsyncd | HIGH | confirmed | https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages |
| 2026-10-12 | icmacos-glowcoma-maas | HIGH | confirmed | https://socradar.io/blog/icmacos-infostealer-rat/ |
| 2026-10-15 | cl-unk-1211-sysgorat | HIGH | confirmed | https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/ |
| 2026-10-21 | litellm-1-107-0-cook-pth | CRITICAL | confirmed | https://www.wiz.io/blog/litellm-compromised-steals-credentials |

### AI tools, MCP and extensions (40 entries)

| Published | Target | Severity | Confidence | Primary source |
|---|---|---|---|---|
| 2026-06-01 | mini-shai-hulud-redhat-mcp | CRITICAL | confirmed | https://osv.dev/vulnerability/MAL-2026-5129 |
| 2026-06-02 | kiro-file-write-autoexec | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-10591 |
| 2026-06-05 | miasma-ai-config-injection | CRITICAL | confirmed | https://safedep.io/miasma-worm-ai-coding-agent-config-injection/ |
| 2026-06-09 | vscode-copilot-chat-2026-patches | HIGH | confirmed | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45482 |
| 2026-06-09 | mcp-server-name-squat-canary | HIGH | confirmed | https://osv.dev/vulnerability/MAL-2026-5479 |
| 2026-06-10 | claude-code-action-pr-mcpjson | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-47751 |
| 2026-06-13 | promptsnatcher-adblockers | HIGH | secondary | https://gbhackers.com/promptsnatcher-browser-extensions-abuse-ai/ |
| 2026-06-15 | cursor-claude-hooks-autoexec | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-48124 |
| 2026-06-15 | glasswasm-openvsx | HIGH | confirmed | https://socket.dev/blog/glasswasm-malware-open-vsx-extensions |
| 2026-06-16 | mcp-credential-stealer-npm | CRITICAL | confirmed | https://osv.dev/vulnerability/MAL-2026-10693 |
| 2026-06-17 | claude-code-webfetch-hf-exfil | CRITICAL | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-54316 |
| 2026-06-24 | gemini-cli-env-override | CRITICAL | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-12537 |
| 2026-06-25 | cursor-sandbox-symlink-write | CRITICAL | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-50549 |
| 2026-06-29 | fastmcp-ssrf-cmdinj | HIGH | confirmed | https://osv.dev/vulnerability/PYSEC-2026-338 |
| 2026-07-08 | cline-websocket-hijack | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-59723 |
| 2026-07-09 | ruflo-mcp-bridge-unauth | CRITICAL | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-59726 |
| 2026-07-16 | mcp-python-sdk-jul-2026 | HIGH | confirmed | https://osv.dev/vulnerability/GHSA-vj7q-gjh5-988w |
| 2026-07-24 | claude-code-worktree-sandbox-escape | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-55607 |
| 2026-08-04 | kiro-windows-search-path | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-18656 |
| 2026-08-04 | shai-hulud-here-we-go-again-mcp | CRITICAL | confirmed | https://osv.dev/vulnerability/MAL-2026-11829 |
| 2026-08-04 | openvsx-evil-twin-mangorbit | HIGH | confirmed | https://www.manifold.security/blog/open-vsx-evil-twin-extensions |
| 2026-08-05 | claude-base-url-hijack-npm | CRITICAL | confirmed | https://osv.dev/vulnerability/MAL-2026-12510 |
| 2026-08-05 | copilot-mcp-apex-dropper | CRITICAL | confirmed | https://osv.dev/vulnerability/MAL-2026-12314 |
| 2026-08-11 | cursor-macos-autorun-sandbox-escape | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-73217 |
| 2026-08-12 | cc-skills-helper-dropper | CRITICAL | confirmed | https://osv.dev/vulnerability/MAL-2026-13933 |
| 2026-08-27 | superior-wallet-drainer-extensions | CRITICAL | confirmed | https://socket.dev/blog/chrome-edge-extension-wallet-drainer |
| 2026-09-01 | codex-git-config-exec | CRITICAL | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-19590 |
| 2026-09-01 | codex-powershell-stop-parsing-bypass | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-19591 |
| 2026-09-03 | vscode-edrtester-domain-fronting | HIGH | confirmed | https://osv.dev/vulnerability/MAL-2026-16010 |
| 2026-09-04 | ai-cli-relay-campaign | HIGH | confirmed | https://osv.dev/vulnerability/MAL-2026-16013 |
| 2026-09-09 | axiom-padre-trader-extensions | HIGH | confirmed | https://socket.dev/blog/chrome-firefox-crypto-data-theft |
| 2026-09-16 | rmcp-oauth-session-2026 | HIGH | confirmed | https://osv.dev/vulnerability/GHSA-33f5-2c5q-wgwj |
| 2026-09-21 | gemini-computer-use-tunnel | CRITICAL | confirmed | https://osv.dev/vulnerability/MAL-2026-16355 |
| 2026-09-23 | memtensor-sckit-openclaw-plugin | CRITICAL | confirmed | https://osv.dev/vulnerability/MAL-2026-16476 |
| 2026-09-30 | jetbrains-ai-skill-autoupdate | MEDIUM | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-100265 |
| 2026-10-07 | claude-code-toctou-symlink-write | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-103435 |
| 2026-10-12 | continue-cli-bash-prefix-bypass | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-109560 |
| 2026-10-13 | claude-code-plugin-hash-pin-bypass | HIGH | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-86063 |
| 2026-10-16 | claude-agent-sdk-resume-flag-injection | CRITICAL | confirmed | https://nvd.nist.gov/vuln/detail/CVE-2026-96620 |
| 2026-10-20 | mcp-ts-sdk-oct-2026 | HIGH | confirmed | https://osv.dev/vulnerability/GHSA-46jr-4wx8-v453 |

### Disagreements between sources (found during collection)

- **GitLab CVE-2026-85706:** the first fix on 2026-09-10 covered only 19.3.2 / 19.2.6 / 19.1.8; 19.0.9 / 18.11.12 were added on 09-23.
- **CVSS divergence:** Atlassian CVE-2026-21589 (CNA 9.3 / NVD 7.5), TeamCity CVE-2026-111094 (8.1 / 9.8) and CVE-2026-106218 (8.8 / 10.0), PHP CVE-2026-17543 (8.1 / 9.8), containerd CVE-2026-53488 (9.4 / 8.8), Gemini CLI CVE-2026-12537 (10.0 / 7.8).
- **Gitea CVE-2026-60004:** KEV says write permission is required, while the NVD CVSS says no authentication is required (PR:N).
- **Argo CD CVE-2026-113672:** NVD's affected range "<3.3.1" does not match 3.3.15 in the description.
- **7-Zip CVE-2026-14266:** NVD lists only 26.01 as affected, but the official history says it was fixed in 26.02.
- **OpenJDK CVE-2026-41254:** a CVE in lcms2. The OpenJDK fixed versions are derived from the next update releases (8u is unknown and not listed).
- **Hash of arrayref 0.3.10:** secondary sources and Wiz disagree. Wiz's value was adopted.
- **ID of Superior (browser extension):** Socket's 32-character form was adopted rather than THN's 31-character form.
- **PamStealer (Wavel variant) and the new MacSync version:** infrastructure, LaunchAgent and strings match (possibly aliases of the same family). Both are recorded as separate campaigns.

## Added in ZES 0.5.2 (2026-10-24): CVE-2026-111497 (Node2Shell / HTTP2Shell)

An out-of-bounds write in the Brotli decoder (`c/dec/decode.c`, CWE-787 / CWE-252). CNA: Google; CVSS 4.0 9.2 (`AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`); published 2026-10-22. Affected: Brotli 1.0.3 to before 1.0.10, 1.1.0 to before 1.1.1, 1.2.0 to before 1.2.1. Exposure needs a path that decodes Brotli from an untrusted peer (`Content-Encoding: br` in a request body, or a response from a server you do not control). Researchers first reported it for Node.js ("Node2Shell"); Aikido later showed that other users of the decoder (Python packages, proxies, HTTP clients) are affected and renamed it "HTTP2Shell". It is the same CVE.

| Target | Value in `rules/ioc.json` | Verdict | Primary source |
|---|---|---|---|
| PyPI `Brotli` | `vulnerable_versions` `>=1.0.3 <1.2.1`, fixed 1.2.1 (HIGH, `s15.pkg_vulnerable_fixed`) | Match | GHSA-9v8h-qqgm-4m35 https://github.com/advisories/GHSA-9v8h-qqgm-4m35 |
| PyPI `brotlicffi` | `vulnerable_versions` `>=1.0.3 <1.2.1.0`, fixed 1.2.1.0 (HIGH) | Match | GHSA-9v8h-qqgm-4m35 |
| Node.js (bundled Brotli) | fixed 22.23.4 / 24.22.1 / 26.12.1 (already present since 5.2.2); `cvss` set from `null` to the CNA's 9.2. Severity stays HIGH (vendor rating high) | Match | CVE record https://cveawg.mitre.org/api/cve/CVE-2026-111497 , https://nodejs.org/en/blog/vulnerability/october-2026-security-releases |

Not imported (could not be confirmed from a primary source on 2026-10-24; reported only by https://www.aikido.dev/blog/python-packages-vulnerable-node2shell-brotli-cve-2026-111497): Bun 1.4.4, Envoy 1.40.0 / 1.39.3 / 1.38.6 / 1.37.8, Istio 1.29.9 / 1.30.6 / 1.31.2, curl/libcurl and OS `libbrotli` packages (distributions backport without changing the upstream version, so a version check would mislead). Check these with your vendor. Node.js 20 and older get no fix. Mitigation where no fix exists (from the same Aikido post): reject `Content-Encoding: br` at the proxy and stop decoding Brotli in clients; removing `br` from `Accept-Encoding` alone is not enough.
