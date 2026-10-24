[English](ioc-verification.md) | 日本語

# ZES v5.2 IoC 一次情報照合レポート

- **調査日**: 2026-10-22
- **対象**: ZES v5.2 Master Specification §3（`rules/ioc.json` 収録データ）＋ §6 / §9 で参照される一部の値
- **方法**: Web 検索で公式アドバイザリ（GitHub Advisory / OSV / NVD / CISA KEV / ベンダー告知）と一次調査元（Socket, StepSecurity, JFrog, Wiz, Snyk, Datadog, Microsoft, Unit 42, Check Point, Elastic, Pillar, Adversa ほか）を照合した。記事の本文を直接取得できず、検索結果の要約を使った項目がある。記載のない値は推測で埋めていない。
- **判定区分**
  - **一致**: 一次情報または複数の一次調査元で仕様の値を確認できた
  - **相違あり**: 事実の一部は確認できたが、値・帰属・説明が仕様と食い違う（内容は備考欄に記載）
  - **確認できず**: 今回の調査範囲では裏付けが見つからなかった、または調査していない

## サマリ

| 判定 | 件数 | 割合 |
|---|---|---|
| 一致 | 68 | 約 59% |
| 相違あり | 24 | 約 21% |
| 確認できず | 23 | 約 20% |
| **合計** | **115** | 100% |

（件数は下の各表の行単位で数えた）

**実装に影響する主な相違（優先度順）**

1. **キャンペーン名と時期の取り違え**: `pypi-oct2026` に含まれる telnyx（2026-03-27）と lightning（2026-04-30）は、どちらも 10 月の事案ではない。certifi は eMudhra 事案（GHSA-6q48-6c7w-9gw2）であり、`litellm-oct2026` キャンペーンに属さない。
2. **jscrambler の悪性版**: 実際は 8.14.0 / 8.16.0 / 8.17.0 / 8.18.0 / 8.20.0 の 5 版。「8.14.0〜8.20.0」の範囲で判定すると、悪性と報告されていない 8.15.0 と 8.19.0 まで誤検知する。安全版は 8.22.0。TeamPCP への帰属は確認できなかった（JFrog は IronWorm 系統と評価）。
3. **trivy-action v0.69.4**: v0.69.4 は Trivy バイナリの版番号であり、trivy-action の版番号ではない。trivy-action はタグ 75/76 が書き換えられ（Aqua 発表では 76/77）、安全版は v0.35.0。
4. **Cursor CVE-2026-50548 の修正版は 3.0**（仕様 §41 の「<2.5」は CVE-2026-26268 のもの）。
5. **CVE-2026-22703 の対象製品は Rekor ではなく Cosign**。版範囲 <2.6.2 / <3.0.4 は一致する。
6. **MCP 系 CVE の説明違い**: CVE-2026-52869 は MCP Python SDK のセッション ID と認証主体を紐付けない不備（CVSS 7.1、修正 1.27.2）で、レジストリ汚染の事案ではない。CVE-2026-58500 は appium-mcp の XSS（8.2）であり、各ソースは RCE と記載していない。GO-2026-6002 は NAT64 の不備ではない（認証ディスカバリ経路の SSRF、CVE-2026-58196）。
7. **NeighborJack の定義**: Backslash Security（2025-06）の報告では「MCP サーバーが 0.0.0.0 に bind し、同一 LAN から到達できる」設定不備を指す。仕様の「隣接する脆弱な MCP 経由の間接侵害／内部 IP の登録」とは検出対象が異なる。
8. **誤検知リスク**: `seed1/seed2.getsession.org`（Session メッセンジャーの正規インフラ）と、`eth-mainnet.nodereal.io` / `go.getblock.io` / `eth.llamarpc.com`（正規の Ethereum RPC）は、名前が出現しただけで CRITICAL にすると誤検知する。
9. **ChainDrop の IoC 不足**: 新しい C2 `awqhnjewqjkl[.]icu` と Ethereum 解決コントラクト `0xE1f2395ee43e45A1556EC6438a88c31B83493103` が仕様に入っていない（Unit 42 / Elastic / Microsoft）。
10. **Homebrew ca-certificates `2026-09-25_1`**: eMudhra の鍵漏洩は 2026-10-17 に報告された。それより前の日付のバンドルが修正版になることはありえず、値の誤りが疑われる（裏付けは取れていない）。

---

## 1. `packages[]`

| 項目 | 仕様値 | 一次情報の値 | 判定 | 根拠URL |
|---|---|---|---|---|
| litellm（悪性版／安全版） | 1.107.0 / 1.106.2 | 1.107.0 の wheel 7 種が悪性。2026-10-21 公開、安全版は 1.106.2（Chainguard） | 一致 | https://research.jfrog.com/post/litellm-hijacked-again/ , https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer , https://www.chainguard.dev/unchained/litellm-attacked-again-malicious-1-107-0-wheels-on-pypi-and-docker-hub-october-2026 |
| litellm（悪性ファイル） | cook.pth / cook.py / sitecustomize.py | cook.pth（`import cook`）→ cook.py、sitecustomize.py のデーモン、`/tmp/remote_code_loader.lock` | 一致 | https://www.mend.io/blog/litellm-1-107-0-compromised/ , https://www.endorlabs.com/learn/litellm-1-107-0-compromised-python-startup-hooks-steal-cloud-ai-and-proxy-credentials |
| litellm（Docker イメージ） | 記載なし | Docker Hub のイメージも侵害された（StepSecurity / Chainguard） | 相違あり（仕様に不足） | https://socket.dev/blog/litellm-compromise |
| certifi | <2026.10.19 / 2026.10.19（campaign: litellm-oct2026） | GHSA-6q48-6c7w-9gw2。影響範囲 2019.03.09〜<2026.10.19（emSign ECC Root CA G3 を削除）。原因は eMudhra 事案で、LiteLLM とは無関係 | 相違あり（キャンペーンの紐付け誤り） | https://www.openwall.com/lists/oss-security/2026/10/20/20 , https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576 |
| @tanstack/*（規模） | 42pkg / 84ver | 2026-05-11 に 42 パッケージ・84 版を公開。GHSA-g7cv-rxg3-hmpx / CVE-2026-45321 | 一致 | https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack , https://advisories.gitlab.com/npm/@tanstack/react-router/CVE-2026-45321/ |
| @tanstack/*（悪性ファイル） | router_init.js / tanstack_runner.js / vite_setup.mjs | 今回の調査ではファイル名を照合できなかった | 確認できず | — |
| mistralai | 2.4.6 / 2.4.5 | PyPI の mistralai 2.4.6 が悪性で、2.4.5 が安全 | 一致 | https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised , https://phoenix.security/mini-shai-hulud-teampcp-tanstack/ |
| guardrails-ai | 0.10.1 / 0.10.0 | 0.10.1 が悪性で、0.10.0 以前は安全 | 一致 | https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack |
| intercom-client | 侵害版 / 「1,800+開発者影響」 | 悪性版は 7.0.4（2026-04-30、約 2 時間公開）、安全版は 7.0.3。GHSA-54pg-9963-v8vg。「1,800+」という数値はどこにも見つからない | 相違あり（版番号が未記載、影響人数の裏付けなし） | https://osv.dev/vulnerability/GHSA-54pg-9963-v8vg |
| jscrambler | 8.14.0〜8.20.0（campaign: teampcp） | 悪性は 8.14.0 / 8.16.0 / 8.17.0 / 8.18.0 / 8.20.0 の 5 版、安全版は 8.22.0。2026-07-11 公開の Rust 製インフォスティーラー。TeamPCP への帰属は確認できず、JFrog は IronWorm 系統と評価 | 相違あり | https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html , https://www.attestd.io/blog/jscrambler-ironworm-npm-supply-chain |
| @asyncapi/* | 侵害版 | 調査していない | 確認できず | — |
| @polymarket/* | 侵害版 | 調査していない | 確認できず | — |
| keyv | 6.0.0 / 5.x 最新 | 6.0.0 は 2026-08-04 公開（MAL-2026-11524）。npm は keyv@5.6.0 を latest に戻した | 一致 | https://osv.dev/vulnerability/MAL-2026-11524 , https://www.chainguard.dev/unchained/the-keyv-and-cacheable-npm-supply-chain-attack-inside-the-mini-shai-hulud-campaign |
| flat-cache | 6.1.24 | 6.1.24 が悪性で、6.1.23 が安全 | 一致 | https://www.stepsecurity.io/blog/chaindrop-npm-worm |
| file-entry-cache | 11.1.6 | Datadog / StepSecurity は 11.1.6 を悪性と記載。Chainguard は版番号を示していない | 一致（ソース間で一部相違あり） | https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/ |
| cacheable-request | 13.0.20 | 13.0.20 が悪性で、13.0.19 が安全 | 一致 | https://www.stepsecurity.io/blog/chaindrop-npm-worm |
| cache-manager | 7.2.10 | 7.2.10 が悪性で、7.2.9 が安全 | 一致 | https://www.chainguard.dev/unchained/the-keyv-and-cacheable-npm-supply-chain-attack-inside-the-mini-shai-hulud-campaign |
| ecto | 5.0.1 | ecto@5.0.1 の setup.mjs と Math_Symbol.js は keyv@6.0.0 のものとバイト単位で同一 | 一致 | https://www.mend.io/blog/keyv-malicious-packages/ |
| cacheable / @cacheable/memory / @cacheable/node-cache / @cacheable/utils / @cacheable/net | 2.5.1 / 2.2.1 / 3.1.2 / 2.5.1 / 2.1.1 | 影響パッケージとしての記載はあるが、版番号を個別に照合できなかった | 確認できず | https://www.stepsecurity.io/blog/chaindrop-npm-worm |
| lightning | 2.6.2, 2.6.3 / 2.6.1 / `_runtime/`（campaign: pypi-oct2026） | 値は一致する（`_runtime` が Bun を取得して実行）。ただし公開日は 2026-04-30 で、10 月の事案ではない | 相違あり（キャンペーン名・時期） | https://lightning.ai/blog/pytorch-lightning-supply-chain-attack/ , https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/ |
| telnyx | 4.87.1, 4.87.2 / 4.87.0 / 83.142.209.203:8080（campaign: pypi-oct2026） | 値は一致する（`http://83.142.209.203:8080/ringtone.wav`、GHSA-955r-262c-33jc）。ただし公開日は 2026-03-27 で、10 月の事案ではない | 相違あり（キャンペーン名・時期） | https://advisories.gitlab.com/pypi/telnyx/GHSA-955r-262c-33jc/ , https://www.akamai.com/blog/security-research/telnyx-sdk-pypi-2026-teampcp-supply-chain-attacks |
| py2ops | 2.2 | 悪性と記載しているのは Vulert のみ。secure.software の 2.2.1 スキャンはマルウェアなしで、両者が矛盾する。版 2.2 は確認できなかった | 確認できず | https://vulert.com/vuln-db/malicious-code-in-py2ops--pypi- , https://secure.software/pypi/packages/py2ops/malware |
| @solana-labs/web3js | 1.0.0, 1.0.2, 100+ / MAL-2026-5788 | MAL-2026-5788（GHSA-pqhf-q5g8-6jpm、2026-06-15）。版リストはソースによって異なる（1.0.0〜1.0.10、1.98.103〜1.98.110、1.98.112 など） | 一致（版リストは OSV の最新版で要確認） | https://osv.dev/vulnerability/MAL-2026-5788 |
| solana-web3-stable | sibling | MAL-2026-10903 | 一致 | https://www.hacktron.ai/package/npm/solana-web3-stable/1.0.0 |
| @solana-labs/spl-toke / web3-js / ancor | sibling | 照合できなかった | 確認できず | — |
| tensorlake | 0.5.144（2026-10-08） | 0.5.144 は 2026-10-08 公開、0.5.143 が最終安全版。preinstall で実行され、トークン失効を検知すると $HOME を消去するスイッチを持つ | 一致 | https://socket.dev/blog/tensorlake-compromise , https://safedep.io/tensorlake-npm-compromise-mini-shai-hulud/ |
| imgdecode（malfex） | shellcode ローダー | 2026-09-30 アップロード。Windows で DLL を介してシェルコードを dllhost.exe に注入する | 一致 | https://thehackernews.com/2026/10/malfex-npm-package-imgdecode-hides.html |
| Namastex Labs 関連 | npm→PyPI→暗号資産 | @automagik/genie、pgserve 等（2026-04）。npm と PyPI に伝播し、ウォレットを窃取する | 一致（時期は 2026-04） | https://www.theregister.com/2026/04/22/another_npm_supply_chain_attack/ |
| css-nesting-transform | 1.0.0（2026-10-12） | MAL-2026-17804。npm 公開は 2026-10-07、OSV の公開は 10-08、最終更新は 10-12。依存関係混乱を狙った偵察型（whoami / id / uname を webhook に送信） | 相違あり（日付） | https://osv.dev/vulnerability/MAL-2026-17804 , https://github.com/ossf/malicious-packages/pull/1602 |
| HF datasets | 悪性データセット（2026-07-16） | Hugging Face が 2026-07-16 に公表。リモートコードローダーとデータセット設定のテンプレートインジェクションの 2 経路 | 一致 | https://huggingface.co/blog/security-incident-july-2026 |
| lerobot | CVE-2026-25874 / CVSS 9.8 | ≤0.5.1 が影響。CVSS は 9.3（GHSA / THN）と 9.8（CSA）でソースによって異なる。公表時点で修正版はなかった | 相違あり（CVSS がソース間で不一致、修正版未確認） | https://labs.cloudsecurityalliance.org/research/csa-research-note-lerobot-cve-2026-25874-unauth-rce-20260429/ , https://thehackernews.com/2026/04/critical-cve-2026-25874-leaves-hugging.html |
| megalodon-ci | 5,561 リポジトリ（2026-05） | 2026-05-18、6 時間未満で 5,561 リポジトリに 5,718 件のコミット | 一致 | https://labs.cloudsecurityalliance.org/research/csa-research-note-megalodon-github-actions-cicd-supply-chain , https://stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories |
| sckit-memos | OpenClaw / MemoryOS（2026-09-23） | npm @memtensor/memos-cloud-openclaw-plugin 0.1.21 / 0.1.23 / 0.1.25、PyPI MemoryOS 2.0.34。C2 は skyleen[.]fr（Socket） | 一致（版番号と C2 は仕様に不足） | https://thehackernews.com/2026/09/compromised-memtensor-packages-deliver.html , https://safedep.io/memtensor-sckit-worm-npm-pypi/ |
| @redhat-cloud-services/* | MAL-2026-5141 / OIDC publisher 侵害 | MAL-2026-5141 は host-inventory-client 5.0.3 / 5.0.4 / 5.0.6 の 1 パッケージのみ。他のパッケージは MAL-2026-5142 / 5143 などの別 ID。OIDC trusted publisher の悪用は一致 | 一致（ID は 1 パッケージ分のみ） | https://osv.dev/vulnerability/MAL-2026-5141 , https://www.bleepingcomputer.com/news/security/red-hat-npm-packages-compromised-to-steal-developer-credentials |
| sap-npm | SAP 関連（2026-05） | 調査していない | 確認できず | — |
| nx-console | 悪性版 | 18.95.0（2026-05-18）、CVE-2026-48027、KEV 掲載、修正版は 18.100.0 | 一致（版番号は仕様に不足） | https://nx.dev/blog/nx-console-v18-95-0-postmortem , https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised |
| ovhcloud-cli | 2026-10-19 リリース / GlassWorm 経由 | v0.11.0〜v0.15.0 のリリースバイナリが 2026-10-19 に差し替えられた。安全版は v0.16.0。侵入経路は開発者の GitHub アカウント侵害。GlassWorm との関連は研究者の仮説で、OVHcloud は言及していない | 相違あり（帰属が未確定） | https://www.helpnetsecurity.com/2026/10/21/ovhcloud-cli-github-malware/ , https://www.securityweek.com/hijacked-developer-account-used-to-plant-stealer-in-ovhcloud-cli/ |
| typosquat-payment-sdk | 決済 SDK のタイポ（2026-06〜07） | 調査していない | 確認できず | — |

## 2. `worm_iocs`

| 項目 | 仕様値 | 一次情報の値 | 判定 | 根拠URL |
|---|---|---|---|---|
| chaindrop.files | setup.mjs / Math_Symbol.js | 同じ 2 ファイル（ドロッパーと第 2 段） | 一致 | https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/ |
| chaindrop.files | math_init.js | 確認できなかった | 確認できず | — |
| chaindrop.preinstall | `node setup.mjs` | preinstall フックで setup.mjs を実行する | 一致 | https://www.mend.io/blog/keyv-malicious-packages/ |
| setup.mjs sha256 #1 | 54dc7ea5…b350668 | 同じ値 | 一致 | https://www.mend.io/blog/keyv-malicious-packages/ |
| setup.mjs sha256 #2 | fd3ca400…5684b1eb | 検索結果に一致するものがなかった | 確認できず | — |
| Math_Symbol.js sha256 | 9fc2570b…cf1bcc | Math_Symbol.js として同じ値。math_init.js にも同じ値を割り当てている根拠は見つからない | 一致（math_init.js 分は確認できず） | https://www.mend.io/blog/keyv-malicious-packages/ |
| chaindrop C2 | npm-cache[.]com / pypi-get[.]com / js-mirror[.]com | 一致。ただし新しい C2 `awqhnjewqjkl[.]icu` と解決コントラクト `0xE1f2395ee43e45A1556EC6438a88c31B83493103` が仕様にない | 相違あり（IoC 不足） | https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/ , https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/ |
| chaindrop RPC | eth-mainnet.nodereal.io / go.getblock.io / eth.llamarpc.com | IoC として列挙されている。ただし正規サービスなので、想定外の CI ランナーからの接続だけを調査対象にすべき | 一致（誤検知に注意） | https://op-c.net/blog/chaindrop-npm-supply-chain-attack/ |
| teampcp.c2_ip | 83.142.209.194 / 94.154.172.43 | どちらも FBI の IoC セットに含まれる | 一致 | https://www.ic3.gov/CSA/2026/260702.pdf , https://research.jfrog.com/post/shai-hulud-here-we-go-again/ |
| teampcp.c2_domains | api.masscan.cloud / git-tanstack.com | キャンペーンの C2 として記載されている | 一致 | https://crimson7.io/resources/blogs/teampcp-mini-shai-hulud-supply-chain-campaign/ |
| teampcp.c2_domains | seed1 / seed2.getsession.org | 窃取データの搬送に使われた。ただし Session メッセンジャーの正規インフラで、DNS 単位での遮断が推奨されている | 一致（誤検知に注意） | https://phoenix.security/mini-shai-hulud-teampcp-tanstack/ |
| teampcp.urls | https://83.142.209.194/v1/weights , /audio.mp3 | 確認できなかった | 確認できず | — |
| teampcp.urls | api.github.com/search/commits?q=FIRESCALE | 確認できなかった | 確認できず | — |
| teampcp.oidc_technique | `/proc/<pid>/mem` から OIDC を抽出 | TanStack の事後報告に「runner のメモリから OIDC トークンを抽出」とある | 一致 | https://corgea.com/research/tanstack-supply-chain-attack-mini-shai-hulud |
| teampcp.deadman_switch | GitHub 認証情報の失効で $HOME を全削除 | 同じ挙動の記録は tensorlake（gh-token-monitor）と Miasma にある。TeamPCP 本体の記録としては、JFrog が「破壊的コマンドを実行する分岐がある」と記載するのみ | 相違あり（帰属が曖昧） | https://socket.dev/blog/tensorlake-compromise , https://research.jfrog.com/post/shai-hulud-here-we-go-again/ |
| post_shaihulud / IronWorm | Rust 製の窃取マルウェア | Rust 製。eBPF ルートキットと Tor C2 を持ち、npm の 36〜37 パッケージに混入（2026-06） | 一致 | https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/ |
| IronWorm masquerade | cargo-install | Cargo では build-script フックを使う。「cargo-install」という名前での偽装は確認できなかった | 確認できず | https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/ |
| sckit | Go 製 / MemOS・MemoryOS / 2026-09-23 | 一致 | 一致 | https://safedep.io/memtensor-sckit-worm-npm-pypi/ |
| miasma.deadman_switch | トークン失効を検知して $HOME を削除 | 失効を検知すると `rm -rf ~/` を実行（最大 72 時間） | 一致 | https://www.bleepingcomputer.com/news/security/the-miasma-worm-source-code-briefly-leaked-on-github/ |
| miasma.leaked_source | 2026-06-10 に一時公開 | The Register によれば 2026-06-08 に公開された（報道は 06-09〜10） | 相違あり（日付） | https://www.theregister.com/cyber-crime/2026/06/09/miasma-supply-chain-attack-toolkit-goes-public-on-github/5253074 |
| miasma の分類 | AI 武器化 | AI コーディングツールの設定を汚染する機能はある。リーク後に悪用された事例は確認されていない（Wiz の McCarthy） | 相違あり（表現が過大） | 同上 |
| quasar_linux（QLNX） | userland LD_PRELOAD + kernel eBPF | `/etc/ld.so.preload` を使う LD_PRELOAD ルートキットと、BPF マップを管理する eBPF 部分（カーネル側プログラムの有無はソースで見解が分かれる） | 一致 | https://labs.cloudsecurityalliance.org/research/csa-research-note-quasar-linux-rat-supply-chain-20260509/ |
| quasar_linux.persistence | systemd / crontab / init.d / XDG / .bashrc | 項目ごとには照合しなかった | 確認できず | — |
| linkpro | eBPF + LD_PRELOAD フォールバック | eBPF Hide モジュールが使えないとき `/etc/ld.so.preload`（`/etc/libld.so`）に切り替える。報告は 2025-10（Synacktiv） | 一致 | https://thehackernews.com/2025/10/linkpro-linux-rootkit-uses-ebpf-to-hide.html |
| voidlink | LD_PRELOAD / LKM / eBPF | 一致（Check Point 2026-01、Elastic の解析） | 一致 | https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/ , https://www.elastic.co/security-labs/illuminating-voidlink |

## 3. `infrastructures[]`

| 項目 | 仕様値 | 一次情報の値 | 判定 | 根拠URL |
|---|---|---|---|---|
| GitLab CVE-2026-110264 | 10.0 / 認証不要の RCE | 10.0、2026-10-21 修正（18.11.13〜19.5.1 の 7 系列）、10-22 時点で KEV 未掲載 | 一致（修正版は仕様に不足） | https://thehackernews.com/2026/10/critical-gitlab-flaw-cvss-100-could.html , https://securityonline.info/gitlab-critical-patch-release-cve-2026-110264/ |
| GitLab CVE-2026-85706 | 10.0 / パストラバーサル | 10.0、commits API 経由の認証不要な任意ファイル読取。修正版 19.1.8 / 19.2.6 / 19.3.2、KEV 掲載は 2026-09-11 | 一致 | https://www.rapid7.com/blog/post/etr-cve-2026-85706-critical-gitlab-path-traversal-exploited-in-the-wild/ |
| GitLab CVE-2026-19478 | 9.4 / GraphQL コードインジェクション | GraphQL コードインジェクションで悪用されたとの言及はある。CVSS 9.4 と影響版は確認できなかった | 確認できず | https://www.securityweek.com/gitlab-vulnerability-exploited-one-day-after-disclosure/ |
| TeamCity CVE-2026-63077 | 9.8 / <2026.1.3, <2025.11.7 / KEV 期限 2026-08-08 | 9.8、修正版 2025.11.7 / 2026.1.3、KEV 掲載は 2026-08-05 で期限 2026-08-08 | 一致 | https://www.rapid7.com/blog/post/etr-cve-2026-63077-critical-unauthenticated-remote-code-execution-in-jetbrains-teamcity/ , https://kev.5sn.com/2026/CVE-2026-63077 |
| Artifactory CVE-2026-82329 | 9.8 / 6 系列の修正版 | 9.8、修正版 7.111.21 / 7.117.28 / 7.125.20 / 7.133.29 / 7.146.38 / 7.161.20。7.111.21 が境界値に含まれるかは JFrog の表記が曖昧 | 一致 | https://docs.jfrog.com/releases/docs/jfrog-security-advisories , https://bishopfox.com/blog/cve-2026-82329-unauthenticated-administrative-access-in-jfrog-artifactory-via-an-empty-cluster-join-key |
| Docker CVE-2026-17106 | CopyEscape（docker cp） | `docker cp` でホスト上の任意ファイルに書き込める（Imperva）。修正が確認できたのは Docker Sandboxes 0.38.0 の `sbx cp` のみで、Docker CLI 側の修正版は見つからない | 一致（修正版は確認できず） | https://www.imperva.com/blog/copyescape-taking-over-docker-hosts-with-docker-cp/ |
| Kernel CVE-2026-31431 | Copy Fail / CISA KEV | KEV 掲載は 2026-05-01（期限 05-15）。修正版 6.18.22 / 6.19.12 / 7.0 | 一致 | https://threatprotect.qualys.com/2026/05/04/linux-kernel-vulnerability-exploited-in-the-wild-copy-fail-cve-2026-31431/ |
| Kernel CVE-2026-80521 | AF_UNIX UAF / コンテナからホスト root / 7.8 | 7.8、SCM_RIGHTS の GC 競合。修正版 6.12.111 / 6.18.53 / 7.1.10 / 7.2（二次情報） | 一致 | https://www.yorku.ca/uit/2026/09/linux-kernel-container-escape-vulnerability-cve-2026-80521/ |
| Kernel CVE-2026-64564 | SCTPhantom / SCTP UAF / 「6/8 でエスケープ成功」 | ASCONF UAF（Tencent Zhuque Lab、2026-08-06）。修正版 6.6.148 / 6.12.101 / 6.18.42 / 7.1.6。「6/8」という成功率は確認できなかった | 相違あり（成功率の裏付けなし） | https://matrix.tencent.com/en/2026/08/06/sctphantom-CVE-2026-64564 , https://blog.cloudlinux.com/sctphantom-cve-2026-64564-local-root-exploit-status-and-fixes-for-cloudlinux/ |
| Sigstore CVE-2026-22772 | Fulcio metaRegex SSRF / <1.8.5 | 一致（GHSA-59jp-pj84-45mr） | 一致 | https://nvd.nist.gov/vuln/detail/cve-2026-22772 |
| Sigstore CVE-2026-22703 | Rekor の任意エントリ受理 / <2.6.2, <3.0.4 | 対象製品は **Cosign**。成果物を参照しない Rekor エントリを含むバンドルでも検証が通る。版範囲は一致 | 相違あり（製品名） | https://osv.dev/CVE-2026-22703 , https://advisories.gitlab.com/pkg/golang/github.com/sigstore/cosign/v2/CVE-2026-22703/ |
| Sigstore CVE-2026-39395 | verify-blob-attestation の偽陽性 / 修正 3.0.6, 2.6.3 | 一致（GHSA-w6c6-c85g-mmv6、4.3） | 一致 | https://nvd.nist.gov/vuln/detail/CVE-2026-39395 |
| Sigstore GHSA-fx35-mq7g-6g98 | レガシーバンドル検証バイパス / 修正 3.1.3 | 公開鍵を使ったレガシーバンドル検証バイパス。v2.6.5 にバックポートされたことは確認できたが、「3.1.3」は確認できなかった | 相違あり（修正版の裏付けが不足） | https://newreleases.io/project/github/sigstore/cosign/release/v2.6.5 |
| Sigstore CVE-2026-31830 | sigstore-ruby / <0.2.3 | 一致（GHSA-mhg6-2q2v-9h2c、7.5） | 一致 | https://nvd.nist.gov/vuln/detail/CVE-2026-31830 |

## 4. `mcp_poisoning` / `ai_coding_assistant`

| 項目 | 仕様値 | 一次情報の値 | 判定 | 根拠URL |
|---|---|---|---|---|
| SymJack | 対象設定ファイル / `ln -s ../.claude/settings.json docs/vid-settings.mp4` | Adversa AI が 2026-05-26 に公表。検出ルール ATR-2026-00572 に同じ例がある。CVE は未割当 | 一致 | https://adversa.ai/blog/the-approval-prompt-is-lying-to-you-symlink-rce-in-five-ai-coding-agents-claude-code-cursor-antigravity-copilot-grok-build/ , https://agentthreatrule.org/zh/rules/ATR-2026-00572 |
| SymJack 対策 | Claude Code v2.1.129+ | 「v2.1.129 で部分的に修正」とする二次情報がある | 一致（二次情報、部分的な修正） | http://sdd.sh/2026/06/symjack-trustfall-rce-ai-coding-agents/ |
| Deadbugz | 最初の 3 回は正常、4 回目以降に悪性化 | 3 回目の tools/call 以降、tools/list と prompts/get の応答が改変される（Pillar） | 一致 | https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign |
| NeighborJack | 隣接する脆弱な MCP 経由の間接侵害 / 内部 IP の登録を検出 | Backslash（2025-06）: MCP サーバーが 0.0.0.0 に bind し、LAN から到達できる設定不備 | 相違あり（定義・検出対象） | https://www.csoonline.com/article/4012712/misconfigured-mcp-servers-expose-ai-agent-systems-to-compromise.html |
| SPECTER MCP-POISON | レジストリ汚染ツール | 該当するものが見つからない | 確認できず | — |
| CVE-2026-52869 | MCP レジストリ供給網 / 7.6 | MCP Python SDK でセッション ID と認証主体が紐付けられていない不備。CVSS 7.1、修正版 1.27.2（GHSA-jpw9-pfvf-9f58） | 相違あり（内容と CVSS） | https://osv.dev/CVE-2026-52869 , https://advisories.gitlab.com/pypi/mcp/CVE-2026-52869/ |
| CVE-2026-58500 | MCP Appium の XSS から RCE | appium-mcp の locator UI の XSS、8.2、修正版 1.85.10（GHSA-x975-rgx4-5fh4）。RCE とは記載されていない | 相違あり（RCE の表現） | https://osv.dev/vulnerability/CVE-2026-58500 |
| CVE-2026-104850 | MCP TS SDK の OAuth 偽装 | 7.5、修正版 1.31.0 / 2.2.0（GHSA-6qxp-vccf-f47h） | 一致 | https://advisories.gitlab.com/npm/@modelcontextprotocol/sdk/CVE-2026-104850/ |
| CVE-2026-104120 | mcp-server-fetch / everything の fetch_url | SSRF（≤2026.6.4）、修正版はまだない | 一致 | https://app.opencve.io/cve/CVE-2026-104120 |
| CVE-2026-111767 | InMemoryTaskStore のアクセス制御不備 | 同種の不備は WS-2026-0090（@modelcontextprotocol/sdk 1.24.0〜1.31.0、修正版 1.32.0）。CVE 番号との対応は確認できなかった | 確認できず | https://mend.io/vulnerability-database/WS-2026-0090/ |
| CVE-2026-59951 | FastMCP のセッション蓄積 | MCP Python SDK の Streamable HTTP でセッションが無制限に溜まる。修正版 1.30.0 / 2.2.0 | 一致 | https://osv.dev/vulnerability/CVE-2026-59951 |
| CVE-2026-61559 | gitlab-mcp のサーバーサイド不備 | @zereight/mcp-gitlab の SSRF でトークンが漏れる。9.6、修正版 2.1.27 | 一致 | https://osv.dev/vulnerability/CVE-2026-61559 |
| ToolHive GO-2026-5996 | IPv6 NAT64 レンジの見落とし | CVE-2026-54450。64:ff9b::/96 と 64:ff9b:1::/48 を見落とす | 一致 | https://osv.dev/vulnerability/GO-2026-5996 |
| ToolHive GO-2026-6002 | NAT64 / host.docker.internal | GO-2026-6002 は認証ディスカバリ経路の SSRF（CVE-2026-58196）。host.docker.internal 経由の横移動は別件の CVE-2026-58197 | 相違あり（混同） | https://advisories.gitlab.com/pkg/golang/github.com/stacklok/toolhive/ |
| Cursor CVE-2026-26268 | 9.9 / 2.5 で修正 | NVD は 9.9、GitHub（CNA）は 8.0。.git の設定・フックへの書き込みによるサンドボックス脱出で、2.5 で修正 | 一致 | https://nvd.nist.gov/vuln/detail/CVE-2026-26268 |
| Cursor CVE-2026-50548 | Zero-Click プロンプトインジェクション（§41 では「<2.5」） | DuneSlide。9.8、`run_terminal_cmd` の working_directory を使ったパストラバーサル。**修正版は Cursor 3.0** | 相違あり（修正版） | https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html , https://www.catonetworks.com/blog/duneslide-two-critical-rce-vulnerabilities |
| EUVD-2026-39537 | CVE-2026-50548 の別名 | 対応関係を確認できなかった | 確認できず | — |
| Cursor CVE-2025-54136 | MCP JSON の Zero-Click 構成 RCE | MCPoison。7.2、1.3 で修正 | 一致 | https://blog.checkpoint.com/research/cursor-ide-persistent-code-execution-via-mcp-trust-bypass/ |
| Cursor git.exe 0-day | 未修正 / リポジトリルートの git.exe を自動実行 | Mindgard が 2026-07-14 に公表（3.2.16 まで未修正）。同じ挙動は Copilot CLI / Gemini CLI / Codex でも報告されている | 一致 | https://www.securityweek.com/unpatched-cursor-vulnerability-exposes-users-to-code-execution/ |
| Copilot CVE-2025-62222 | 信頼ダイアログ表示前のコマンド実行 | VS Code Copilot Chat 拡張のコマンドインジェクション（8.8、修正版 0.32.5）。「信頼ダイアログ表示前」の実行は確認できなかった | 相違あり（説明） | https://osv.dev/vulnerability/CVE-2025-62222 |
| Copilot CVE-2026-50510 | JetBrains 版のローカルコード実行 | 7.8、<1.13.0（CWE-641） | 一致 | https://app.opencve.io/cve/CVE-2026-50510 |

## 5. `github_actions` / `browser_extensions`

| 項目 | 仕様値 | 一次情報の値 | 判定 | 根拠URL |
|---|---|---|---|---|
| trivy-action | v0.69.4（76 タグ中 75 が汚染、2026-03） | 2026-03-19 に trivy-action のタグ 75/76 が強制 push された（Aqua 発表では 76/77）。**v0.69.4 は Trivy バイナリ**の悪性版。安全版は trivy-action v0.35.0 / trivy v0.69.3 | 相違あり（版番号の対象） | https://snyk.io/articles/trivy-github-actions-supply-chain-compromise/ , https://thehackernews.com/2026/03/trivy-security-scanner-github-actions.html |
| megalodon | 5,561 リポジトリ / 2026-05 | 一致（2026-05-18） | 一致 | https://labs.cloudsecurityalliance.org/research/csa-research-note-megalodon-github-actions-cicd-supply-chain |
| mass_workflow_planting / GhostAction | 500+ アカウント / 2026-10-07 以降 | Socket: 2026-10-07〜09 に 500+ アカウントが「security audit」に偽装したワークフローをコミット | 一致 | https://breached.company/ghostaction-returns-malicious-github-actions-workflow-hits-500-accounts-tens/ |
| mass_workflow_planting.stolen_secrets | PyPI / npm / DockerHub | 照合できなかった | 確認できず | — |
| ghostaction 偽装フォント | 偽装フォントにインフォスティーラーを隠し、第 2 ワークフローも設置 | 偽装フォント（`public/fonts/fa-solid-400.woff2`、94 リポジトリ、tasks.json の folderOpen で起動）は、500 アカウント波とは**別の後続／模倣活動**として報告されている | 相違あり（2 つの事案を混同） | https://thehackernews.com/2026/10/ghostaction-attackers-plant-credential.html , https://opensourcemalware.com/blog/ghostaction-copycats-polinrider-by-hiding-a-stealer-in-a-fake-font-file |
| 19 件の Chrome/Edge 拡張（所有権移転） | 2026 | 「19 件」という数値は確認できなかった | 確認できず | — |
| Save Image as Type | 100 万+ ユーザー、アフィリエイト詐欺 | 一致（Karma が 2025-11 に買収） | 一致 | https://www.techspot.com/news/111737-popular-chrome-extension-save-image-type-hijacked-impacting.html |
| QuickLens | 約 7,000 ユーザー | 一致（2026-02-17 に悪性更新） | 一致 | https://cyberwarzone.com/2026/03/16/chrome-extensions-turned-malicious-after-ownership-transfer-pushing-code-injection-and-fake-updates/ |
| ShotBird | 約 800 ユーザー | 一致 | 一致 | 同上 |
| GlassWorm | WebSocket RAT | 調査していない | 確認できず | — |
| ModHeader | 署名済み正規拡張に休眠中の窃取コード | 7.0.18 に休眠コード。約 160 万インストール、2026-07 にストアから削除。拡張 ID は idgpnmonknjnojddfkpgkljpfnnfcklj | 一致（ID は仕様に不足） | https://vpncentral.com/modheader-extension-with-1-6-million-installs-contained-dormant-data-exfiltration-code/ |

## 6. その他（§6 / markers / process_signatures）

| 項目 | 仕様値 | 一次情報の値 | 判定 | 根拠URL |
|---|---|---|---|---|
| eMudhra テストホスト | dv-g3b-emudhra.we-have-a-problem.com（接続成功＝CRITICAL、SSL エラー＝SAFE） | 公式テストページにこのホスト名がある（ほかに dv-g3b-aaa-emudhra）。「証明書エラー＝侵害された中間 CA を信頼していない」 | 一致 | https://emudhra.we-have-a-problem.com/ |
| eMudhra 事案の時期 | — | Mozilla への報告は 2026-10-17、中間 CA 8 件の秘密鍵が漏洩 | 一致（参考） | https://bugzilla.mozilla.org/show_bug.cgi?id=2083449 |
| Homebrew ca-certificates | 2026-09-25_1+ | 事案（10-17）より前の日付で、修正版としては矛盾する。裏付けは取れていない | 確認できず（誤りの疑い） | — |
| Go 1.27.3 / 1.26.10 | eMudhra 対応版 | 確認できなかった | 確認できず | — |
| marker | /tmp/remote_code_loader.lock | litellm 1.107.0 の IoC として記載がある | 一致 | https://www.mend.io/blog/litellm-1-107-0-compromised/ |
| process_signatures | litellm.dev | 偽ドメイン `www.litellm.dev` への送信 | 一致 | https://www.upwind.io/feed/litellm-1-107-0-supply-chain-attack-malicious-code-found-in-pypi-package |

---

## 確認できなかった項目一覧

（関連する行をまとめて記載しているため、表の「確認できず」23 行とは 1 対 1 に対応しない）

1. @tanstack/* の悪性ファイル名（router_init.js / tanstack_runner.js / vite_setup.mjs）
2. @asyncapi/*（未調査）
3. @polymarket/*（未調査）
4. cacheable 2.5.1 / @cacheable/memory 2.2.1 / @cacheable/node-cache 3.1.2 / @cacheable/utils 2.5.1 / @cacheable/net 2.1.1 の個別の版番号
5. py2ops 2.2（ソース間で矛盾）
6. @solana-labs/spl-toke / web3-js / ancor
7. sap-npm（未調査）
8. typosquat-payment-sdk（未調査）
9. chaindrop の math_init.js
10. setup.mjs の 2 つ目のハッシュ fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb
11. teampcp の URL（/v1/weights、/audio.mp3、FIRESCALE）
12. IronWorm の cargo-install 偽装
13. QLNX の永続化手法の個別項目
14. GitLab CVE-2026-19478 の CVSS 9.4 と影響版
15. SPECTER MCP-POISON
16. CVE-2026-111767（WS-2026-0090 と同一かどうか）
17. EUVD-2026-39537
18. GhostAction の窃取対象（PyPI / npm / DockerHub）
19. 19 件の Chrome/Edge 拡張（所有権移転）
20. GlassWorm（未調査）
21. Homebrew ca-certificates 2026-09-25_1
22. Go 1.27.3 / 1.26.10

**調査していない範囲**: §3.6〜§3.12 のうち CVE / キャンペーン名を含まない手法記述（`dangerous_patterns`、`build_hooks`、`persistence`、`anti_forensics` の一般的な手法）、`process_signatures` の残り（letters9813 / pythonclient-test / PRIVCOLLECT / npm-cache / math_init）、`markers` の `/tmp/.pc_once_*`、§9.4 の Djinn / OmniStealer、§5 の Python 3.15.1 / 3.14.9 / 3.13.17。

---

## 5.2.1 での反映（2026-10-22）

ユーザー承認に基づき、一次情報で確認できた相違を `rules/ioc.json` と `zes-scan.sh` に反映した。確認できなかった値（「確認できず」の行）は変更せず、必要なものに注記を付けた。

| 項目 | 変更内容 | 根拠（本レポートの行） |
|---|---|---|
| certifi | campaign を `litellm-oct2026` → `emudhra-ca-oct2026`、範囲を `>=2019.3.9 <2026.10.19` に | certifi 行（GHSA-6q48-6c7w-9gw2） |
| intercom-client | 侵害版 7.0.4・安全版 7.0.3 を設定、「1,800+」の記述を削除 | intercom-client 行（GHSA-54pg-9963-v8vg） |
| jscrambler | 悪性版を 8.14.0 / 8.16.0 / 8.17.0 / 8.18.0 / 8.20.0 に限定、安全版 8.22.0、campaign を `jscrambler-jul2026` に分離（TeamPCP 帰属は未確認） | jscrambler 行 |
| lightning / telnyx | 値は据え置き。公開日（04-30 / 03-27）と GHSA を注記 | 各行 |
| css-nesting-transform | MAL-2026-17804・公開日 10-07 を注記 | 同行 |
| lerobot | 影響範囲 `<=0.5.1` を設定（CRITICAL）。CVSS のソース間不一致を注記 | lerobot 行 |
| ovhcloud-cli | 影響 v0.11.0〜v0.15.0、安全版 v0.16.0。GlassWorm 帰属は未確定と注記 | ovhcloud-cli 行 |
| ChainDrop | C2 `awqhnjewqjkl[.]icu` と解決コントラクト `0xE1f2…3103` を追加。Ethereum RPC 3 ホストは `legit_infra`（MEDIUM）へ | chaindrop C2 / RPC 行 |
| TeamPCP | `seed1/seed2.getsession.org` を `legit_infra`（MEDIUM）へ。deadman_switch の帰属が曖昧なことを注記 | teampcp 各行 |
| Miasma | 公開日 06-08、「AI 武器化」の表現を修正 | Miasma 行 |
| GitLab CVE-2026-85706 | 修正版 19.1.8 / 19.2.6 / 19.3.2 を設定（§3 で CRITICAL 判定）。110264 は系列別修正版が未確認のため注記のみ | GitLab 行 |
| Kernel | Copy Fail / CVE-2026-80521 / SCTPhantom の修正版を設定（§23 で HIGH 判定）。「6/8」の記述を削除 | Kernel 行 |
| Docker CVE-2026-17106 | CLI の修正版が未確認であることを注記 | Docker 行 |
| CVE-2026-22703 | 対象製品を Cosign に修正。§43 の Rekor イメージ判定を削除 | Sigstore 行 |
| GHSA-fx35-mq7g-6g98 | 2.x 系の修正版 2.6.5 を追加（3.1.3 は未確認と注記） | 同行 |
| NeighborJack | 定義を「0.0.0.0 での待ち受け」に修正（§20 は従来どおり両方を検出） | NeighborJack 行 |
| CVE-2026-52869 / 58500 | mcp_cves へ移動し、`mcp<1.27.2` / `appium-mcp<1.85.10` を §37 で HIGH 判定 | 各行 |
| ToolHive | GO-2026-6002 と CVE-2026-58197 の取り違えを修正 | ToolHive 行 |
| Cursor CVE-2026-50548 | 修正版 3.0 を設定（§41 で <3.0 を CRITICAL） | Cursor 行 |
| Copilot CVE-2025-62222 | Copilot Chat 拡張 <0.32.5 を §41 で HIGH 判定、説明を修正 | Copilot 行 |
| trivy-action | v0.69.4 は Trivy 本体の版と修正。trivy-action は v0.35.0 以外のタグ参照を CRITICAL、Trivy 本体 v0.69.4 の指定を CRITICAL | trivy-action 行 |
| GhostAction | 偽装フォント事案が別件であることを注記 | ghostaction 行 |
| Homebrew ca-certificates | 基準値の誤りが疑われるため、判定を HIGH → MEDIUM（要確認）に変更 | Homebrew 行 |

`incident_bundle` は `ZES-2026-OCT-EMERGENCY-V5.2` のまま（findings.json スキーマの形式 `V<major>.<minor>` を維持するため）。

## 5.2.2 で追加した収集インテル（2026-10-22）

2026-06〜10 に公開された脅威情報を、各ベンダー・研究機関の一次情報（NVD / CISA KEV / GHSA / OSV / ベンダー公告・研究ブログ）から収集し、`rules/ioc.json` の `packages[]`・`infrastructures[]`・`intel` に取り込みました。`verification` が `secondary` のものは一次情報に到達できず二次報道で補ったものです（検知はしますが、値の確度は一次情報より低い）。

取り込みの方針:

- **誤検知の抑制:** 汎用的なファイル名（`index.js`・`build.rs`・`settings.json` など）、汎用的な文字列、正規サービスのドメイン単体（github.com・api.telegram.org など）は照合に使いません。正規サービス上の特定 URL は `legit_infra`（MEDIUM）として扱います。
- **重大度:** 悪性パッケージは CRITICAL、脆弱版（悪性ではなく CVE の影響範囲）は `match: vulnerable_versions` で HIGH です。ローカルツールのバージョン判定はディストリビューションのバックポートを考慮して上限を HIGH にしています。
- **未対応（静的に判定できないもの）:** GitHub Enterprise Server・Tekton Pipelines-as-Code・Docker Sandboxes・7-Zip・Git for Windows（イメージ名・バイナリから版を取れないか、Windows のみ）、sudo CVE-2026-82474（修正版不明）、Jenkins Script Security プラグイン（プラグイン版の取得手段なし）、Windows 版 Kiro。データとしては記録しています。

### パッケージ（41 件）

| 公開日 | 対象 | 重大度 | 確度 | 一次情報 |
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

### CI/CD（24 件）

| 公開日 | 対象 | 重大度 | 確度 | 一次情報 |
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

### 開発インフラ・ランタイム CVE（47 件）

| 公開日 | 対象 | 重大度 | 確度 | 一次情報 |
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

### ホスト（インフォスティーラー・永続化）（29 件）

| 公開日 | 対象 | 重大度 | 確度 | 一次情報 |
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

### AI ツール・MCP・拡張（40 件）

| 公開日 | 対象 | 重大度 | 確度 | 一次情報 |
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

### 情報源間の食い違い（収集時に判明したもの）

- **GitLab CVE-2026-85706:** 2026-09-10 の初回修正は 19.3.2 / 19.2.6 / 19.1.8 のみで、19.0.9 / 18.11.12 は 09-23 に追加。
- **CVSS の乖離:** Atlassian CVE-2026-21589（CNA 9.3 / NVD 7.5）、TeamCity CVE-2026-111094（8.1 / 9.8）・CVE-2026-106218（8.8 / 10.0）、PHP CVE-2026-17543（8.1 / 9.8）、containerd CVE-2026-53488（9.4 / 8.8）、Gemini CLI CVE-2026-12537（10.0 / 7.8）。
- **Gitea CVE-2026-60004:** KEV は書込権限が必要とし、NVD の CVSS は認証不要（PR:N）。
- **Argo CD CVE-2026-113672:** NVD の影響範囲「<3.3.1」が説明文の 3.3.15 と不一致。
- **7-Zip CVE-2026-14266:** NVD は 26.01 のみを影響版とするが、公式履歴では 26.02 で修正。
- **OpenJDK CVE-2026-41254:** lcms2 の CVE。OpenJDK の修正版は次期アップデート版からの導出（8u は不明のため未記載）。
- **arrayref 0.3.10 のハッシュ:** 二次情報と Wiz で不一致。Wiz の値を採用。
- **Superior（ブラウザ拡張）の ID:** THN の 31 文字表記ではなく Socket の 32 文字表記を採用。
- **PamStealer（Wavel 亜種）と MacSync 新版:** インフラ・LaunchAgent・文字列が一致（同一ファミリーの別名の可能性）。両方を別キャンペーンとして収録。

## ZES 0.5.2 で追加（2026-10-24）: CVE-2026-111497（Node2Shell / HTTP2Shell）

Brotli デコーダ（`c/dec/decode.c`）の境界外書込（CWE-787 / CWE-252）。CNA は Google、CVSS 4.0 9.2（`AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`）、2026-10-22 公開。影響: Brotli 1.0.3 以上 1.0.10 未満、1.1.0 以上 1.1.1 未満、1.2.0 以上 1.2.1 未満。信頼できない相手の Brotli を展開する経路（リクエスト本文の `Content-Encoding: br`、自分が管理しないサーバーからの応答）があるときに影響します。最初は Node.js の問題（「Node2Shell」）として報じられ、Aikido がデコーダを使う他のもの（Python のパッケージ、プロキシ、HTTP クライアント）も影響を受けると示して「HTTP2Shell」と呼び直しました。同じ CVE です。

| 対象 | `rules/ioc.json` の値 | 判定 | 一次情報 |
|---|---|---|---|
| PyPI `Brotli` | `vulnerable_versions` `>=1.0.3 <1.2.1`、修正版 1.2.1（HIGH、`s15.pkg_vulnerable_fixed`） | 一致 | GHSA-9v8h-qqgm-4m35 https://github.com/advisories/GHSA-9v8h-qqgm-4m35 |
| PyPI `brotlicffi` | `vulnerable_versions` `>=1.0.3 <1.2.1.0`、修正版 1.2.1.0（HIGH） | 一致 | GHSA-9v8h-qqgm-4m35 |
| Node.js（同梱の Brotli） | 修正版 22.23.4 / 24.22.1 / 26.12.1（5.2.2 から登録済み）。`cvss` を `null` から CNA の 9.2 に更新。重大度はベンダー評価 high に合わせ HIGH のまま | 一致 | CVE レコード https://cveawg.mitre.org/api/cve/CVE-2026-111497 、https://nodejs.org/en/blog/vulnerability/october-2026-security-releases |

取り込まなかったもの（2026-10-24 時点で一次情報を確認できず、https://www.aikido.dev/blog/python-packages-vulnerable-node2shell-brotli-cve-2026-111497 だけが報告）: Bun 1.4.4、Envoy 1.40.0 / 1.39.3 / 1.38.6 / 1.37.8、Istio 1.29.9 / 1.30.6 / 1.31.2、curl/libcurl と OS の `libbrotli` パッケージ（ディストリビューションは上流の版番号を変えずにバックポートするため、版番号の比較は誤判定になる）。これらは各ベンダーで確認してください。Node.js 20 以前には修正がありません。修正がない場合の緩和策（同じ Aikido の記事より）: プロキシで `Content-Encoding: br` を拒否し、クライアントで Brotli の展開を止める。`Accept-Encoding` から `br` を外すだけでは足りません。
