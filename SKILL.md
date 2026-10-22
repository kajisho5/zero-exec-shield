---
name: zes-scan
description: Zero-Exec Shield (ZES) v5.2 の検知スキル。サプライチェーン攻撃・CA危殆化・インフラRCE・AI開発環境トラップ・SkillPact契約乖離を、対象を一切実行しない静的解析で検疫し findings.json を出力する。新規脅威インテリジェンスから IoC を抽出して rules/ioc.json を拡張する「IoC抽出モード」も持つ。検知のみ（read-only）で、判断は ZET（zero-exec-triage）、修復は GER（gated-exec-remediation）が担う。
---

# ZES 検知スキル（zes-scan）

- **incident_bundle**: `ZES-2026-OCT-EMERGENCY-V5.2`
- **層**: 検知層（read-only）。判断・修復は行わない

```
[検知スキル] zes-scan … read-only、契約検証、乖離検出
      ↓ findings.json（skillpactフィールド付き）
[判断スキル] ZET（zero-exec-triage） … 乖離の影響判定、例外承認
      ↓ remediation-plan.json
[修復スキル] GER（gated-exec-remediation） … 明示承認後のみ実行
```

## 絶対ルール

1. **Zero-Execution**: 検査対象のコード・スクリプト・パッケージを実行しない。`npm install` / `pip install` / `php` によるスクリプト実行 / `node` / `python` による対象コードの読み込み / フィクスチャやスキルの `.sh` 実行は禁止。
2. **内容非読取**: 検出結果としてファイル内容を出力・引用しない。パス・重大度・メタ情報（サイズ・mtime・ハッシュ）のみ扱う。
3. **改変しない**: 検査対象・SkillPact 契約・ポリシー・L2 記録・署名ファイルを書き換えない。
4. **fail-closed**: `status` が `partial` / `error`、または `errors[]` が空でない場合、該当モジュールは「未確定」と報告する。0 件を安全と言い換えない。
5. **L3 署名は信頼の根拠にしない**: L3 は「署名済みファイル」の証明であり、安全性・作者の信頼性の証明ではない。差分異常と併せて扱う。

## 検知モード

```bash
./zes-scan.sh --quick     --root <dir> --json   # §1〜19
./zes-scan.sh --standard  --root <dir> --json   # §1〜35
./zes-scan.sh --full      --root <dir> --json   # §1〜49
./zes-scan.sh --worm      --root <dir> --json   # §15/18/25/45
./zes-scan.sh --skillpact --root <skills-dir> --json [--skillpact-cache <dir>]   # §49
```

手順:

1. ユーザーが指定したディレクトリを `--root` に渡す。不明なら確認する（勝手に `/` や `~` を走査しない）。
2. `--json` で実行し、標準出力の findings.json を保存する（標準エラーは人間向けログ）。
3. 結果を報告する: `status`、重大度別件数、CRITICAL/HIGH の `module`・`campaign`・`path`・`detail`、`errors[]`（未確定モジュール）。
4. SkillPact の finding は `skillpact.divergence`・`policy_decision`・`l2_tested`・`signed`・`diff_anomaly` を併記する。`signed: true` を「安全」と表現しない。
5. 修復手順を提案する場合も実行はしない。ZET に渡す findings.json のパスを示して終える。

報告に含めないもの: ファイルの中身、シークレットの値、トークン文字列。

## IoC 抽出モード（§8.1）

新規脅威インテリジェンス（URL / テキスト）から次を抽出し、`rules/ioc.json` への追記案を作る。

1. `campaign` 名（`teampcp-mini-shai-hulud` / `chaindrop-keyv` / `pypi-oct2026` / `solana-typosquat` / `post-shaihulud` / `symjack` / `deadbugz` / `neighborjack` / `skillpact-*` 等）
2. パッケージ名・侵害バージョン・安全バージョン（`bad_versions` と `safe_version` の両方）
3. 悪性ファイル名・ハッシュ（SHA-256 のみ）
4. ネットワーク IoC（C2 ドメイン / IP / Exfil 先。`[.]` 形式で無害化、URL は `hxxp` 表記）
5. インフラ CVE（TeamCity / Artifactory / GitLab / Docker / Kernel / Sigstore のバージョン範囲と修正版）
6. 検出手法（preinstall フック / SymJack / OIDC 窃取 / ランタイムゲート / 所有権移転拡張 / ビルドフック / モデルサプライチェーン / アンチフォレンジック / eBPF / LD_PRELOAD）
7. SkillPact: 契約のエフェクト宣言パターン、契約と実態が乖離した事例（未宣言の `exec`/`network`/`secrets`）、アカウント侵害型の差分異常（同一作者の急激なエフェクト拡大）、prose と契約の矛盾パターン、破壊的マーカー・永続化マーカーの新規パターン

抽出時の注意:

- 一次情報（ベンダー公式アドバイザリ、GitHub Advisory、OSV、NVD、CISA KEV、レジストリ公式）で裏付けを取り、根拠 URL を併記する。確認できない値は「未確認」と明記し、推測で埋めない。
- 情報源間で矛盾がある場合は両方を記録し、採用値とその理由を示す。
- 既存データとの照合結果は `docs/ioc-verification.md` の形式（一致 / 相違あり / 確認できず）で残す。

## マージルール（§8.2 / §13）

- 既存 `ioc.json` と重複する場合は `campaign` 単位でマージする。
- `incident_bundle` を `ZES-2026-OCT-EMERGENCY-V5.2` に更新する（バンプ時は `zes-scan.sh` の `INCIDENT_BUNDLE` と `CHANGELOG.md` も更新）。
- 孤立 IoC 禁止（全エントリを `campaign` に紐づける）。
- `packages[]` は grep フォールバックのため **1 エントリ 1 行** で書く。
- 追記後に `tests/fixtures/` へ再現フィクスチャを追加し、`tests/run-tests.sh --sync-campaigns` で `rules/campaigns/*.json` を再生成、`tests/run-tests.sh` と `tests/zero-exec.sh` を通す。

## 判断層・修復層への受け渡し

- 検知スキルは findings.json を出力して終わる。例外承認・期限設定は ZET、変更操作は GER の責務。
- 判断層は findings の `id` / `level` / `module` を改変しない。修復層は findings.json を直接読まない（`docs/skill-contracts.md` 参照）。
