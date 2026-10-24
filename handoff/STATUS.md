# バグ探しの中断記録（2026-10-24）

ユーザーの指示（トークン使用量が多いため一旦停止）で中断。実行中の担当はすべて停止済み。

## 現在の main / リリース
| リポジトリ | main | 版 |
|---|---|---|
| ZES zero-exec-shield | 045be3e | v0.5.4（リリース済み） |
| ZET zero-exec-triage | f0dbbf8 | ラウンド 6 まで反映 |
| GER gated-exec-remediation | b73b5ce | ラウンド 6 まで反映（ger-hazards-4） |

ラウンド 4〜6 の確定バグはすべて修正・マージ済み。

## ラウンド 7（未修正、報告は `handoff/r7/`）
確定 26 件（高 4）。各報告に再現手順あり。
- **ZES（20 件, 予定 0.5.5）**: `r7/cli.md`（7 件）、`r7/ui.md`（11 件）、`r7/zetger.md` の F1（JSONC の U+0001）
  - 高: `[ "s"][core] fsmonitor` の見逃し（CLI/UI, 本物の git で再現済み）／ symlink の include の解決ずれ（再現済み）／未展開サブモジュール `.git/modules/**` 未検査／filter・pager など git が実行する設定キーが検査対象外
  - 修正担当は着手直後に停止。**ZES 側のコミットなし**（ブランチ未作成扱い）
- **GER / ZET（6 件）**: `r7/zetger.md` F2〜F7 + E2E がファイルの日付に依存する件
  - 修正担当が途中まで実装しコミット済み、**検証は未完了**（テスト・E2E・kill sweep 未確認）。push のみ、PR なし:
    - GER `claude/r7-fixes` @ 40c4157（9 commits）
    - ZET `claude/r7-fixes` @ 603d985（4 commits）

## 再開手順
1. GER / ZET の `claude/r7-fixes` を `tests/run-tests.sh` と E2E で検証し、不足を補って PR → マージ
2. ZES 0.5.5 を `r7/*.md` の判断（修正担当への指示内容は下記）で実装
3. ラウンド 8 → 確定 0 件のラウンドが出るまで繰り返す

## ZES 0.5.5 の判断（決定済み）
- Git 設定: 空セクション名・include は git と同じ（パスは記載どおり、深さ制限）、バイト単位で解析、include パスの NUL で打ち切り
- git の公式ドキュメントから、リポジトリ設定で実行されるキーを洗い出して §26 に追加（status/checkout 等で動くもの CRITICAL、他 HIGH）、実 git で確認するフィクスチャ（git 2.43/2.55 どちらでも通る比較）
- `.git/modules/**` と構造上の git ディレクトリをすべて検査
- Dockerfile は BuildKit のパーサに完全準拠
- json_view は jq に依存せず共通の緩い読み取り（全エスケープ復号）
- JSONC 読み取りはどのバイトでも壊れない実装、参照パーサとの差分テスト
- HOME の `~/.claude/settings.json` にもフック規則
- UI: 大きな配列の spread 禁止、s49.divergence.write を finding に、正規表現を POSIX の行の意味に統一、見えない文字の目印を Unicode データから
- 2 MiB の緩い読み取りと大量の include を数秒に
