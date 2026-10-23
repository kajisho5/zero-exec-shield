# zero-exec shield Web UI：shadcn/ui 再スタイリング詳細設計書 v2（「検疫台」案）

- 対象: [`ui/`](../../ui/)（Vite＋React＋TypeScript＋Tailwind CSS v4。成果物は単一ファイルの `index.html`）
- 版: 0.2（2026-10-23）。v0.1（リポジトリには含めていない）の見た目の部分を作り直した版。ZES 0.3.0 で実装した
- 状態: §16 の 9 項目はオーナー承認済み（§16）。新しい条件は「AIっぽいデザインはやめて」。**この文書とモックアップは設計だけで、どのリポジトリのコードも変更していない。**
- 付随資料（設計作業用のディレクトリにあり、**このリポジトリには含めていない**。現在の見た目の基準は実装（[`ui/src`](../../ui/src/)）と e2e（[`ui/tests/e2e`](../../ui/tests/e2e/)）。以下は記録として残す）:
  - モックアップ: `overview-dark.svg` / `overview-light.svg` / `skillpact-dark.svg` / `skillpact-light.svg` / `mobile-overview-dark.svg` / `mobile-overview-light.svg` / `mobile-menu-dark.svg` / `tokens.svg`。PNG は `mock-png/`
  - 一覧画像: `sheet.png`（v2 のモックアップ）、`current.png`（現状のスクリーンショット。元画像は `current/`）
  - パレットとコントラストの計算結果: `palette.json`（`scripts/palette.py` が出力し、基準を下回る組み合わせがあれば終了コード 1 で止まる）
  - 生成スクリプト: `scripts/`（`lib.py`、`mockups.py`、`skillpact.py`、`tokens.py`、`render.mjs`、`sheet.py`。撮影と CSP 実測の `shots.mjs`、`csp-test.mjs`、`attr.mjs`、`ref18.mjs` は v0.1 のものをそのまま残した）
- 旧設計書 [ui-design.md](ui-design.md) の要件（F-01〜F-13、N-01〜N-08）、状態管理、エンジンはすべて引き継ぐ。変えるのは見た目とコンポーネントの実装基盤だけ。

> 表記: 【事実】は公式ドキュメントか実測で確かめたこと、【設計判断】はこの文書での判断、【未検証】はまだ確かめていないこと。

### v0.1 からの変更点

| 区分 | v0.1 | v0.2 |
|---|---|---|
| 方向性 | shadcn の既定に近い見た目。紺の地にブランドのブルーを主色にした | 「検疫台」: 実行せずに読む作業の道具立て（作業台、台紙、検体票、押印）から決めた（§5） |
| 色 | 紺 `#060a13` と明るいブルー 1 色 | 地と部品は無彩色（墨と鉛筆）。**色は検出（重大度）と L3 の紫印だけ**（§5.2） |
| 面の作り | すべてカード（角丸 12、同じ枠と影） | 台紙は 3 枚だけ（検体票、検出一覧、SkillPact の報告）。ほかは作業台の上に直接置く（§7） |
| サマリ | 大きな数字のカード 4 枚と、同じ内容のフィルタチップの列 | 1 本の「集計」に統合し、それ自体を重大度フィルタにした（§10.3） |
| 投入欄 | 大きなドロップ領域と貼り付け欄のカード | スキャン後は「検体票」になる。貼り付け判定は右の欄外へ（§10.3） |
| 文言 | 既存の文言 | 中黒で並べた付帯情報をやめ、ラベルと値の組か読点にした。変更の一覧は §10.7 |
| 技術調査 | — | **変更なし**（CSP、Radix Tabs の manual、バンドルの見積もり、forwardRef と React 19、Web フォントを同梱しないこと） |

---

## 1. 目的と非目的

### 1.1 目的
1. 見た目の質と一貫性を上げる。画面ごとに直書きした色（`bg-[#0b1f2a]`、`hover:bg-[#242424]` など）をセマンティックトークンと共通部品にまとめる。
2. **既定の見た目にしない**。この道具の主題（コードを実行せずに読んで判定する）から見た目を決める（§5）。shadcn/ui と Radix は部品の土台として使うが、shadcn の既定の見た目は残さない。
3. ブランドを正しく使う。Fresnel 型の盾のアイコンと、小文字のワードマーク「zero-exec shield」。
4. モバイル（375px、最小 320px）で使えるようにする。特に**スマホで検出のパスが見えない**問題を直す。
5. 18 タブを探しやすくする（cmdk によるタブ検索）。
6. ライトテーマを追加する。既定はダーク（承認済み §16-1）。
7. 制約（§2）は一つも緩めない。CSP は**変えない**（§4.2）。

### 1.2 非目的
- 判定エンジン（[`ui/src/engine`](../../ui/src/engine/)）、状態（[`ui/src/state`](../../ui/src/state/)）、タブ定義（[`ui/src/tabs/definitions.ts`](../../ui/src/tabs/definitions.ts)）、ファイル読み取り（[`fileReader.ts`](../../ui/src/fileReader.ts)）の変更。
- 機能の追加と削除。例外は「タブ検索」「テーマ切替」「モバイルの詳細シート」の 3 つ（いずれも承認済み）。
- Next.js、RSC、`next-themes` など、Vite の単一ファイル構成に合わないもの。

---

## 2. 制約と適合チェック

| ID | 制約 | 現状 | この設計での扱い |
|---|---|---|---|
| C-01 | 単一ファイルにビルドする（`inline-build.mjs` が JS と CSS を 1 つずつ埋め込む） | 満たす | 変えない。依存はすべてビルド時に取り込む |
| C-02 | 外部通信ゼロ（CDN、Web フォント、`fetch` を使わない） | `verify-no-network.mjs` と E2E で確認 | Web フォントは同梱しない（§6）。アイコンは lucide-react のパスをビルド時に取り込む |
| C-03 | ハッシュ方式の CSP。`style-src 'sha256-<CSS>'` の 1 つだけで、`'unsafe-inline'` なし | 満たす | **CSP は変えない**。実行時に `<style>` を差し込むライブラリは使わないか置き換える（§4.2） |
| C-04 | `file://` で動く（オフライン） | 満たす | Radix の Portal は `document.body` に描画するだけで URL を使わない（§4.2） |
| C-05 | WCAG 2.1 AA（文字 4.5:1、UI 部品 3:1、キーボード操作、フォーカス表示） | ほぼ満たす | 全トークンの組み合わせを `palette.py` で計算（§5.2、§5.3）。フォーカスは墨の 2px の輪郭＋2px の空き。色相を使わないので、どの地の上でも 9.4:1 以上 |
| C-06 | 日本語 UI（CJK の組版） | system-ui | §6 |
| C-07 | 18 タブ（§7.2 の順序は固定） | タブバー＋「すべてのタブ」メニュー | Radix Tabs（manual）＋ Command によるタブ検索（§10.2） |
| C-08 | 検出一覧の仮想スクロール | 自作（行の高さ 50px 固定） | 自作のまま。行の高さは 60px（デスクトップ）と 96px（<640px）に固定 |
| C-09 | 重大度の色は互いに区別でき、文字はコントラスト基準を満たす | 一部不足（§3） | 赤・橙・黄・青・灰・緑・紫の 7 色相。両テーマで、淡色地・作業台・台紙・浮き・選択行のすべての上で 4.98:1 以上（§5.3） |
| C-10 | **L3 を「安全」を思わせる色で表示しない** | 紫。満たす | 紫の押印（二重枠）だけ。緑、ティール、主色（墨）は使わない。チェック形のアイコンも使わない（§5.3） |
| C-11 | 320px まで崩れない（横スクロールなし） | E2E で確認 | ブレークポイントごとに設計する（§8） |
| C-12 | 依存を最小にする（供給網リスク。旧設計書 §3） | 実行時の依存は react と react-dom のみ | 増える。内訳は §4.3。lockfile と `--ignore-scripts` を維持する |
| C-13 | ブランドのアイコンの色（紺のスクワークル、ティール→ブルーの盾）をそのまま使える | — | アイコンは自前の紺の地を持つので、作業台（ダーク #252220、ライト #e8e6e3）のどちらに置いても形が崩れない。ワードマークの色（暗い地では #F5F5F7、明るい地では #1D1D1F）は作業台に対して 14.52:1 と 13.51:1。**ティールとブルーは UI のどこにも使わない**ので、アイコンと意味の色がぶつからない |
| C-14 | `prefers-reduced-motion` を尊重する | 満たす | 自動で動くものは置かない。シートとポップオーバーの出入りは reduce のとき 0ms（§7） |

---

## 3. 現状と v0.1 のレビュー

### 3.1 現状の良い点（残す）
- 情報の構成: 入力 → 状態表示 → サマリ → フィルタ → 検出一覧。右に Blast Radius、CLI の案内、未判定。
- 重大度を色だけで伝えない（ラベルとアイコンの形を併記する）。
- L3 は紫で「署名済みファイル」と書き、SkillPact タブでは SAFE を出さない。
- 「0 件 ＝ 安全」と誤解させない文言（CLI の案内、未判定の欄）。
- タブの WAI-ARIA 操作（矢印キーで移動し Enter で選ぶ手動アクティベーション）と、件数入りの `aria-label`。

### 3.2 現状の弱い点（v0.1 から引き継ぐ。対応は v0.2 のもの）
Chromium（`/opt/pw-browsers`）で 作業ツリーの `index.html` を `file://` で開き、フィクスチャを投入して撮影した（`scripts/shots.mjs` → `current/`）。【事実】ライトを指定しても表示は同じ（ダーク固定）。

| # | 画面 | 問題 | v0.2 の対応 |
|---|---|---|---|
| W-1 | モバイル・総合 | 検出一覧が横スクロールの表のままで、375px ではパスの列が画面外にある | 640px 未満は 1 件 96px の行。パスを 2 行目に必ず出す（§10.4） |
| W-2 | モバイル・ヘッダー | ロゴ、bundle ID、状態、ボタン 2 つが 3 段に折り返す | 52px の 1 段。操作は「…」メニューへ（§10.1） |
| W-3 | モバイル・タブ | 見えるタブが約 1 枚。メニューは細いドロップダウン | 44px のタブ列＋検索ボタン → 下からのシート（`mobile-menu-dark.svg`） |
| W-4 | 全体 | 見出しの日本語が単語の途中で折り返す | `word-break: auto-phrase`、短い文言（§6、§10.7） |
| W-5 | ヘッダー | 「オフライン・外部通信ゼロ」が SAFE と同じ緑で、結果が安全と読まれうる | 無彩色のタグ（wifi-off）（承認済み §16-9） |
| W-6 | 総合 | サマリカード 4 枚の枠がすべて重大度色。押した／押していないの差が不透明度だけ。しかも直下のフィルタチップと同じ操作が二重にある | 集計とフィルタを 1 本に統合。押した＝左の帯＋チェック＋色、押していない＝鉛筆色＋空の枠（§10.3） |
| W-7 | 全体 | トークン外の色の直書きでライトテーマが作れない | トークンに一本化（§5） |
| W-8 | 検出一覧 | 列見出しの行が `role="table"` の外にある | 見出し行を table の中の `rowgroup` に入れる |
| W-9 | 貼り付け欄 | 「判定する」が primary で、空でもフォルダ選択と同じくらい強い | outline にし、入力があるときだけ有効 |
| W-10 | Blast Radius | 「パス一覧をコピー」が 375px で 2 行に折り返す | アイコン＋短いラベル、`whitespace-nowrap` |
| W-11 | 全体 | 11px の注記が多い | 日本語は最小 12px。補足文（鉛筆）は 5.46:1 以上（§5.2） |
| W-12 | ブランド | 盾が lucide 風の線画で、名前が「Zero-Exec Shield」 | ブランドのロゴ SVG を使い、小文字で書く |

### 3.3 AIっぽさの監査（frontend-design スキルの一覧で照合）

スキルが挙げる「生成されたデザインが集まりやすい特徴」に、現状の UI（`current.png`）と v0.1 の提案（`sheet.png`（v0.1、リポジトリには含めていない））を照らした。

| # | 特徴（スキルの分類） | 現状 | v0.1 | v0.2 での扱い |
|---|---|---|---|---|
| A-1 | 暗い地に明るいアクセント 1 色（2） | 黒 `#0a0a0a` にティールの主ボタン | 紺 `#060a13` に明るいブルーの主色。紺＋ブルーそのもの | 作業台は明るめのグラファイト（L 0.255）。主ボタンは墨。**色相は検出と押印にしか使わない** |
| A-2 | 黒の代わりの色付きの黒（5） | `#0a0a0a`、`#0b1f2a` | `#060a13` | 地は黒に寄せない。ダークの作業台は `#252220`（読み物の地として明るさを確保）、台紙は `#2e2c29` |
| A-3 | 同じ角丸・同じ枠・同じ影のカードの並び（4） | 入力、サマリ 4 枚、一覧、右の 3 枚がすべて `rounded-xl` のカード | 同じ。角丸 12 を全カードに、ライトでは全カードに `shadow-xs` | 台紙は検体票・検出一覧・報告の 3 枚だけ。右の欄は作業台に直接置き、罫で区切る。角丸は役割ごと（押印 2、タグ 3、台紙 4、部品 6、シート 14）。影は浮くもの（ポップオーバー、シート、トースト）だけ |
| A-4 | 飾りのグラデーション（4） | なし | タブ列の端のフェード | なし。デスクトップのタブは収まる分だけ出して残りは検索へ。モバイルは切れた文字がスクロールの合図 |
| A-5 | 大きな数字＋小さなラベル＋色（ヒーローの既定） | サマリカード 4 枚（30px の数字） | 同じ（32px） | 集計の 1 本にまとめた（21px）。数字は墨、色は語とアイコンにだけ付ける |
| A-6 | 英大文字のラベル（5） | CRITICAL などの小見出し、`SAFE` | 同じ。英大文字に字間 +0.2px | 英大文字は**重大度の値（CLI と findings.json と共通の列挙値）だけ**。字間は付けない。小見出しとしての英大文字は使わない。`SAFE` を見出しにするのもやめた（§10.7） |
| A-7 | 見出しの上の小さなラベル（5） | サマリカードの「CRITICAL」が数字の上 | 同じ。ツールバーの「重大度」 | なくした。ラベルを置くのは**検体票だけ**（実際に記入欄のある書式だから） |
| A-8 | 中黒でつないだ付帯情報 `A · B · C`（5） | 「スキャン完了 ・ 4 ファイル ・ 0.0 秒」「author ・ version」「12 ルール・該当 3・…」 | 同じ。モバイルの「§15 ・ chaindrop-keyv」も | ラベルと値の組（検体票、SkillPact の事実欄）か、読点の文にした。和語の並列（「表示・保存・送信」）は日本語の正しい中黒なので残す |
| A-9 | 小さなデータラベルに等幅（5） | bundle の見出し、モジュール | 版、bundle の Badge、モジュール `§15`、ルール番号 `01` | 等幅は**端末に打ち込める文字列だけ**（パス、コマンド、bundle ID、エフェクト名）。版、`§15`、ルール番号、件数は和文と同じ書体の等幅数字 |
| A-10 | ボタンやリンクの末尾の「→」（5） | 「→ 右パネル参照」 | — | 削除。矢印は Blast Radius の「手順」（実際に順序がある）にだけ残す |
| A-11 | 意味のない連番 `01 / 02`（設計原則） | ルール番号を 0 埋めの等幅 | 同じ | ルールの番号は仕様の ID なので残すが、0 埋めをやめて普通の数字にした |
| A-12 | 「WORD — 断片」型のラベル（5） | なし | モックアップの見出しなど | UI の文言では使わない |
| A-13 | 一律の登場アニメーション・ホバー効果（設計原則） | なし | `zoom-in-95` をポップオーバーとツールチップ全部に | ズームをやめた。動くのは操作への応答だけ（シートが下から出る、ポップオーバーが 120ms で現れる） |
| A-14 | shadcn の既定の見た目（今回の条件） | — | new-york の Button、outline の Badge のピル、Card をほぼ既定のまま | Badge のピルは使わない（タグは角丸 3 の四角）。Card は台紙 3 枚だけ。Button は墨・outline・ghost の 3 種に絞った |
| A-15 | 新聞風の罫線＋角丸ゼロ＋密な段組（3） | — | — | **v0.2 の注意点**。罫を多く使うので、罫は記録の区切り（表の行、書式の欄、欄外の節）にだけ使う。角丸は残し、段組は 2 列まで |
| A-16 | 生成り色＋明朝の見出し＋テラコッタ（1） | — | — | **ライトテーマの注意点**。作業台は彩度 0.004 の灰（`#e8e6e3`）で生成り色にしない。明朝もテラコッタも使わない |

---

## 4. 技術調査（確かめた事実）

> v0.1 の調査をそのまま引き継ぐ（変更なし）。文中の `lab/`、`lab19/`、`lab/out/` は v0.1 のフォルダ `../design-shadcn/` の下にある。

### 4.1 shadcn/ui の現状（2026-10-23 時点の公式ドキュメント）

| 項目 | 内容 | 出典 |
|---|---|---|
| Tailwind v4 と React 19 | 「Tailwind v4 and React 19. Ready for you to try out」。既存の Tailwind v3 / React 18 のアプリも動く。「新しく追加したコンポーネントは、アップグレードするまで v3 と React 18 のまま」 | https://ui.shadcn.com/docs/tailwind-v4 |
| forwardRef を廃止 | 「We've removed the forwardRefs」。primitive にはすべて `data-slot` 属性が付く | 同上 |
| tw-animate-css | `tailwindcss-animate` をやめて `@import "tw-animate-css";` にする | 同上 |
| OKLCH | 色は HSL から OKLCH に変わった。`:root` と `.dark` を `@layer base` の外に出し、`@theme inline` で `--color-*` にマップする | 同上、https://ui.shadcn.com/docs/theming |
| トークン名 | background, foreground, card(-foreground), popover(-foreground), primary(-foreground), secondary(-foreground), muted(-foreground), accent(-foreground), destructive, border, input, ring, chart-1〜5, sidebar-*。`--radius: 0.625rem` | https://ui.shadcn.com/docs/theming |
| 手動導入 | `shadcn class-variance-authority cn lucide-react tw-animate-css` を入れ、CSS の先頭は `@import "tailwindcss"; @import "tw-animate-css"; @import "shadcn/tailwind.css"; @custom-variant dark (&:is(.dark *));` | https://ui.shadcn.com/docs/installation/manual |
| Vite | `@/*` のパスエイリアス、`resolve.alias`、`shadcn init` | https://ui.shadcn.com/docs/installation/vite |
| ダークモード（Vite） | `ThemeProvider` が `document.documentElement` に `light` か `dark` のクラスを付ける。保存先は localStorage の `vite-ui-theme`。system のときは `matchMedia('(prefers-color-scheme: dark)')` に従う | https://ui.shadcn.com/docs/dark-mode/vite |
| components.json | `style` は `"new-york"`（default は廃止）。`tailwind.config` は v4 では空にする。`baseColor` は neutral / stone / zinc / mauve / olive / mist / taupe | https://ui.shadcn.com/docs/components-json |
| プリミティブの選択 | コンポーネントのページに Base UI / React Aria / Radix UI のタブがある（例: Tabs。`variant="line"` と `orientation="vertical"` がある） | https://ui.shadcn.com/docs/components/tabs |
| Native Select | ネイティブの `<select>` を包むだけで、Radix に依存しない | https://ui.shadcn.com/docs/components/native-select |
| Command | cmdk を使う。`CommandDialog` がある | https://ui.shadcn.com/docs/components/command |
| Toast と Sonner | tailwind-v4 のページには「toast を廃止して sonner にする」とある。一方、現在の `/docs/components/sonner` は「Toast」のページ（Base UI / React Aria / Radix の各版）を表示し、Sonner には触れていない。**ドキュメント間で食い違っている**（【未検証】どちらが最新の方針か。changelog は未確認） | 上記 2 ページ |
| レジストリ（new-york-v4） | 【事実・実測】`https://ui.shadcn.com/r/styles/new-york-v4/<name>.json` の依存は次のとおり。tabs / dialog / sheet / tooltip / dropdown-menu / toggle-group / badge = `cn` と `radix-ui`（統合パッケージ）。command = `cn` と `cmdk`。native-select = `cn` のみ。sonner = `sonner` と `next-themes`。どのソースにも `forwardRef` はない | `lab/reg-*.json` |

補足:
- `cn`（npm の `cn@0.5.0`、shadcn-ui/cn リポジトリ、メンテナは shadcn 1 名）は「clsx と tailwind-merge の代わり」。バンドルへの追加は +26.6 KiB（min）。npm 上のパッケージ名自体は 2013 年からある。【設計判断】供給網リスクを考え、**`cn` パッケージは入れず `clsx` と `tailwind-merge` を固定版で使う**（`lib/utils.ts` の `cn()` を自分で持つ。旧来の shadcn と同じ形）。サイズはほぼ同じ。
- `radix-ui`（統合パッケージ 1.8.1）は依存として Radix の全パッケージ（約 60）を node_modules に入れる。バンドルはツリーシェイクされるので同じ大きさ。【設計判断】**導入するのは個別の `@radix-ui/react-*` だけ**にし、shadcn のソースの `import { X } from "radix-ui"` を `import * as X from "@radix-ui/react-x"` に書き換える（入るパッケージを減らし、監査の範囲を狭くする）。

### 4.2 CSP の実測（Chromium、`file://`）

**現行の CSP**（[`ui/scripts/inline-build.mjs`](../../ui/scripts/inline-build.mjs) が生成するもの）:
```
default-src 'none'; script-src 'sha256-<app.js>'; style-src 'sha256-<app.css>'; img-src data:;
font-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'
```

**CSP3 での扱い（仕様の整理）**: `style-src-elem` と `style-src-attr` が無いので、どちらも `style-src` で判定される。
- `<style>` 要素（`style-src-elem`）: 内容のハッシュが一致するものだけ適用される。**実行時に追加した `<style>` も同じ判定を受ける**。
- style 属性（`style-src-attr`）: `'unsafe-inline'` が無いのでブロックされる（ハッシュは `'unsafe-hashes'` を付けない限り属性には効かない）。
- **CSSOM での操作（`el.style.height = …`、`el.style.cssText = …`、`setProperty`）は CSP の対象外**。React の `style={{…}}` は CSSOM で書くので許可される。

**実測結果**（`scripts/attr.mjs`、`scripts/csp-test.mjs`。Chromium 1194 で `file://` から実行）:

| 操作 | 結果 | 違反として報告されたディレクティブ |
|---|---|---|
| HTML に書いた `style="…"` | ブロック | style-src-attr |
| `setAttribute('style', …)` | ブロック | style-src-attr |
| `innerHTML` に含まれる style 属性 | ブロック | style-src-attr |
| `el.style.height = …` / `el.style.cssText = …` | **適用される** | なし |
| React の `style={{height: 33}}` | **適用される** | なし |
| Radix Popper（floating-ui）の位置指定（`transform: translate(...)`） | **適用される** | なし |
| 実行時に作った `<style>`（ハッシュが一致しない） | ブロック | style-src-elem |

**Radix / shadcn の関連ライブラリで実行時に `<style>` を差し込むもの**（`lab/node_modules` を grep で調べ、実測で確かめた）:

| ライブラリ | 差し込む内容 | 中身 | 何もしなかった場合の影響 | 対処 |
|---|---|---|---|---|
| `react-remove-scroll`（Radix の Dialog/Sheet、DropdownMenu、Popover、Select が依存。`react-style-singleton` を使う） | スクロールロックの CSS と `.block-interactivity-<id>` | **実行時に決まる**（スクロールバーの幅や ID を含む）ので、ハッシュでは許可できない | ダイアログやメニューを開くたびに CSP 違反がコンソールにエラーとして出る（既存 E2E の「CSP 違反なし」テストが落ちる）。背面のスクロールロックも効かない | **ビルド時のエイリアスで、CSSOM でロックする自作の互換モジュールに差し替える**（`resolve.alias: { 'react-remove-scroll': './src/lib/remove-scroll-csp.tsx' }`）。`lab/src/remove-scroll-shim.jsx` で実測し、違反ゼロ、`body.style.overflow = hidden` が効く、Dialog のフォーカストラップも動くことを確かめた |
| `@radix-ui/react-scroll-area` | スクロールバーを隠す固定の CSS（169 文字） | 固定 | 違反 1 件 | **使わない**（ネイティブのスクロール＋`scrollbar-width: thin`） |
| `@radix-ui/react-select` | 同様の固定 CSS | 固定 | 開いたときに違反 | **使わない**（Native Select を使う） |
| `sonner` | 約 15 KB の固定 CSS を `__insertCSS` で `<head>` に入れる。空の `<style>` を先に追加してから中身を入れる | 固定 | トーストのスタイルが当たらない（`position: static`） | **使わない**（既存の自作トーストを shadcn の見た目にする）。採用する場合は「CSS のハッシュ」と「空文字列のハッシュ」を `style-src` に足せば違反ゼロになる（実測済み） |
| cmdk | `style` プロパティ（CSSOM）のみ | — | なし | そのまま使える |
| Radix FocusGuards / VisuallyHidden / Tooltip / Tabs / Popper | CSSOM のみ | — | なし | そのまま使える |

**結論**: 【事実】互換モジュールで差し替え、ScrollArea / Select / Sonner を使わなければ、**現行の CSP のまま違反ゼロ**で動く（`lab/out/csp-extra.html` で Tabs / DropdownMenu / Dialog / Tooltip / Popover＋cmdk / Toast を操作し、`securitypolicyviolation` が 0 件、コンソールのエラーも 0 件）。**CSP の変更は提案しない**。
- 【未検証】Firefox と WebKit での同じ実測。CI の `E2E_ALL_BROWSERS=1` で確かめる（移行のステップ 2）。
- 【設計判断】nonce 方式（`get-nonce` の `setNonce`）は採らない。静的ファイルの nonce は誰でも読める固定値になり、意味がないため。

**Portal と `file://`**: Radix の Portal は `document.body` の直下に描画するだけで、URL もオリジンも使わない。`file://` で Tooltip、Popover、Dialog、DropdownMenu が正しい位置に出ることを確かめた。注意点が 1 つある。Portal の中身は `<main role="tabpanel">` の外に描画されるので、E2E で `getByRole('tabpanel').locator(...)` を使って Portal 内の要素を探すと見つからない（§14）。

**React 18 との相性（重要）**: 【事実・実測】new-york-v4 の部品は forwardRef を使わない関数コンポーネントで、`ref` を props で受け取る（React 19 の書き方）。React 18 で `<PopoverTrigger asChild><Button/></PopoverTrigger>` のように使うと、次の 2 つが起きる（`lab/out/ref18.html`）。
- `Warning: Function components cannot be given refs` がコンソールにエラーとして出る（E2E が落ちる）。
- Popper がトリガーの位置を測れず、`transform: translate(0px, -200%)` になる（**メニューが正しい位置に出ない**）。

React 19.3.1 にすると直る（`lab19/`）。対処は 2 案あり、**案 A に決定した（§16-2）**。
- **案 A（採用）: React 19 に上げる**（移行のステップ 0 として単独で行い、既存の E2E が全部通ることを確かめる）。shadcn の部品を書き換えずに使える。代償は JS +79 KiB（min、react-dom 19 が大きい）。
- 案 B: React 18 のままにし、`asChild` の子になる部品（Button、Badge など）だけ `React.forwardRef` で包む。サイズは増えないが、shadcn の更新を取り込むたびに書き換えが要る。

### 4.3 バンドルサイズの見積もり（実測）

esbuild 0.25.10 で minify し、React 18.3.1 だけのベースライン（142.4 KiB）からの増分を測った。測定は `lab/`。

| 構成 | +min | +gzip |
|---|---|---|
| @radix-ui/react-tabs | 28.3 KiB | 9.6 KiB |
| @radix-ui/react-dialog（Sheet 兼用） | 41.8 | 13.9 |
| @radix-ui/react-tooltip | 56.9 | 19.9 |
| @radix-ui/react-popover | 70.0 | 24.4 |
| @radix-ui/react-dropdown-menu | 95.1 | 31.7 |
| @radix-ui/react-toggle-group | 26.1 | 8.9 |
| @radix-ui/react-select（不採用） | 93.1 | 31.9 |
| @radix-ui/react-scroll-area（不採用） | 24.6 | 7.7 |
| cmdk | 52.0 | 17.5 |
| sonner（不採用） | 34.5 | 9.4 |
| clsx + tailwind-merge + cva | 28.0 | 8.7 |
| lucide-react（31 アイコン） | 約 15 | 約 5 |
| **推奨セット**（Tabs, Dialog, Tooltip, Popover, DropdownMenu, ToggleGroup, Separator, Slot, cmdk, cva, cn 相当, lucide 31 個, remove-scroll 互換モジュール）※ | **163.1 KiB** | **54.2 KiB** |
| 参考: React 18 → 19.3.1 | +78.6 KiB | +22.7 KiB |

※ 各パッケージの増分の合計は、共通部分（Popper、DismissableLayer、FocusScope、Portal、Presence など）を重複して数えるので、セットの値より大きくなる。

**成果物 `index.html` の見積もり**（現在 443 KiB = JS 416 + CSS 19 + HTML。ioc.json の約 180 KiB を含む）:
- React 18 のまま（案 B）: JS 約 +163 KiB、CSS 約 +8 KiB（トークンが 2 テーマ分、tw-animate-css で使うユーティリティのみ）→ **約 610 KiB（+38%）**
- React 19（案 A）: **約 690 KiB（+56%）**
- 自作の Button / Icon / Toast / Pill を消す分で −3〜5 KiB 程度。
- `file://` では gzip 転送がないので、効くのは解析時間だけ。【未検証】ミッドレンジ端末での起動時間。目標は「既存の 20,000 ファイルの性能テストが劣化しないこと」。
- 減らす余地: tailwind-merge をやめて `clsx` だけにする（約 −25 KiB。クラスの上書きを使わない規約にする必要がある）。Tooltip をやめてネイティブの `title` と `aria-label` にする（約 −20 KiB。ただしキーボードでは見えない）。

依存パッケージの増加（供給網）: 実行時の依存が react と react-dom の 2 つから約 30（@radix-ui/* と、@floating-ui、aria-hidden、react-remove-scroll-bar、use-callback-ref、use-sidecar、detect-node-es、get-nonce、tslib、cmdk、clsx、tailwind-merge、class-variance-authority、lucide-react）に増える。【設計判断】全件をバージョン固定し、`npm ci --ignore-scripts` を維持する。導入時に各パッケージの publish 日時と provenance を確かめ、`verify-no-network.mjs` の静的検査も通す。

---

---

## 5. 方向性とデザイントークン

### 5.0 コンセプト「検疫台」

ZES はコードを**実行せずに読む**。その作業に近いのは、税関や検疫所で検体を台に広げ、開けずに中を調べて記録を付ける仕事だ（ブランドのタグラインも「実行ゼロのサプライチェーン検疫」）。そこで画面を、**作業台の上に検体票と検査記録が置かれている**ものとして組む。

道具立てとその使い方:

| 検疫台の道具 | 画面での役割 |
|---|---|
| 作業台（地） | ページの地。何も主張しない無彩色。部品と欄外の注記はここに直接置く |
| 台紙 | 読む対象を載せる面。**検体票、検出一覧、SkillPact の報告の 3 枚だけ** |
| 検体票 | 投入したフォルダの記録。検体（`chaindrop/`）、ファイル数、判定時間、未判定、**実行 0 回**。この画面でいちばん目立つ要素 |
| 記録の溝（ガター） | 検出の行の左端。重大度の色の帯と、形＋語の印をここに付ける。レビューで紙の余白に付ける印と同じ |
| 欄外 | 右の列。貼り付け判定、Blast Radius、CLI の案内、未判定の内訳。カードにせず、罫で区切った注記として置く |
| 押印（紫インク） | L3 だけに使う二重枠の印。印は「押されている」ことしか示さず、中身が正しいとは言わない。L3 の意味（署名ファイルがあること。安全ではない）とそのまま一致する |
| 破線 | まだ無いもの（ドロップ先、該当なし、判定不可）。**安心させる色を付けない** |

**大胆にするのは 1 か所だけ**。検体票のパスを等幅の 26px で大きく組み、その横に「実行 0 回」を書く。これがこの製品の約束そのものなので、飾りではなく記録として見せる。ほかはすべて静かにする。

### 5.1 トークン計画：初稿、自己レビュー、改訂

スキルの手順どおり、まず初稿を作り、「似た依頼（セキュリティのダッシュボード）なら誰が作っても同じになるか」で見直した。

**初稿**
- 色: 紺の地 `#0f1626`、台紙 `#162033`、主色はブランドのブルー `#3A6BFF`、フォーカスはブランドのティール `#3DDCC4`、文字 `#e8edf5`、補足 `#94a3b8`。
- 書体: system-ui＋等幅。等幅は数値ラベルにも使う。
- レイアウト: 入力カード、大きな数字のサマリカード 4 枚、フィルタチップ、表、右に 3 枚のカード（v0.1 と同じ骨組み）。
- 原則: 「ブランドの色を UI 全体に通す」。

**自己レビューで既定と判断して直したもの**

| # | 初稿 | 既定だと判断した理由 | 改訂 |
|---|---|---|---|
| R-1 | 紺の地＋ブルーの主色 | A-1 の典型。セキュリティ製品ならどこでもこうなる | 無彩色のグラファイトと紙。主ボタンは墨 |
| R-2 | ブランドの色を UI に通す | 重大度だけで 7 色相（赤・橙・黄・青・灰・緑・紫）が要る。そこにブルーとティールを足すと LOW や SAFE と区別しにくい。ティールは SAFE の緑に近い（v0.1 のリスク R-10） | **色は検出と押印だけ**。ブランドの色はアイコンの中にだけある |
| R-3 | フォーカスがティール | 同上。緑系の輪が SkillPact で「安全」に見える | 墨の 2px の輪郭＋2px の空き。どの地でも 9.4:1 以上 |
| R-4 | サマリカード 4 枚 | A-5 の既定。しかもフィルタチップと機能が重複している | 集計の 1 本にまとめ、それをフィルタにする |
| R-5 | 右の列の 3 枚のカード | A-3 のカードの並び | 欄外の注記。台紙は「読む対象」だけ |
| R-6 | 数値ラベルに等幅 | A-9 | 等幅は端末に打ち込める文字列だけ |
| R-7 | 状態の行「スキャン完了 ・ 4 ファイル ・ 0.0 秒」 | A-8 | 検体票の欄（ラベルと値） |
| R-8 | ダークの作業台が L 0.235（`#201e1b`） | 描いてみると A-2 の「色付きの黒」に近かった | L 0.255（`#252220`）に上げ、台紙・浮き・凹み・罫・縁も同じだけ上げた（コントラストは再計算して全項目合格） |
| R-9 | 欄外の見出しの前にアイコン（鍵、端末、i） | 見出しごとのアイコンは飾りで、見出しの文字で足りる | 外した（「鏡を見て 1 つ外す」） |
| R-10 | L3 は紫の Badge＋スタンプのアイコン | Badge のピルは shadcn の既定（A-14） | 二重枠の押印。アイコンは使わない |

**改訂後のトークン計画**（確定値は §5.2）

- 色（名前の付いた 6 色。テーマごと）:

  | 名前 | 役割 | ダーク | ライト |
  |---|---|---|---|
  | 作業台 bench | ページの地 | `#252220` | `#e8e6e3` |
  | 台紙 sheet | 検体票・検出一覧・報告 | `#2e2c29` | `#fefdfc` |
  | 墨 ink | 本文、主ボタンの塗り、フォーカス、選択中のタブの線 | `#efece7` | `#211d19` |
  | 鉛筆 pencil | 補足文、押していない状態 | `#b9b5b0` | `#57534e` |
  | 罫 rule | 区切り線（飾り） | `#4b4945` | `#d1cfcc` |
  | 紫印 signed | L3 の押印だけ | `#d2b1f9` | `#713dab` |

  補助: 浮き raised（ポップオーバー、シート、トースト）、凹み well（入力欄、コードの欄、表の見出し）、選択行 select（hover と選択中）、縁 edge（入力欄とボタンの枠。1.4.11 の 3:1 用）。
- 書体: 和文と UI は system-ui（ヒラギノ角ゴ、Noto Sans JP、Yu Gothic UI に落ちる）。コードは ui-monospace。2 書体はまったく違う形なので役割が見分けられる（§6）。
- レイアウト: 左寄せ。主列（検体票 → 集計 → 検出一覧）と欄外（右 320px）の 2 列。中央揃えは空の状態のドロップ先だけ（§8）。
- 原則:
  1. 色は証拠。色相が付いているものは、すべて検出か押印である。
  2. 台紙に載るのは読む対象だけ。道具（ボタン、フィルタ、注記）は作業台に置く。
  3. 破線は不在。ドロップ先、該当なし、判定不可。どれも安心の色を付けない。
  4. 等幅は打ち込める文字列だけ。パスはディレクトリを鉛筆、ファイル名を墨にする。
  5. ラベルは書式にだけ付ける（検体票）。見出しの上に飾りのラベルを置かない。

### 5.2 セマンティックトークン（確定値）

shadcn の変数名をそのまま使い、値を「検疫台」の名前に割り当てる。部品のソースは手で取り込む（承認済み §16-6）ので、shadcn の既定のクラスもあわせて書き換える（§9）。色空間は OKLCH。色相 75 の彩度 0.004〜0.010 は「わずかに温かい灰」で、生成り色にも紺にも寄らない。

| shadcn の変数 | 検疫台の名前 | ダーク OKLCH | hex | ライト OKLCH | hex |
|---|---|---|---|---|---|
| `--background` | 作業台 | 0.255 0.006 75 | #252220 | 0.925 0.004 75 | #e8e6e3 |
| `--card` | 台紙 | 0.295 0.006 75 | #2e2c29 | 0.995 0.002 75 | #fefdfc |
| `--popover` | 浮き | 0.335 0.007 75 | #393633 | 1 0 0 | #ffffff |
| `--muted`、`--secondary` | 凹み | 0.225 0.006 75 | #1d1b19 | 0.955 0.004 75 | #f2f0ed |
| `--accent` | 選択行 | 0.355 0.007 75 | #3e3b38 | 0.945 0.006 75 | #efece8 |
| `--foreground`、`--primary`、`--ring` | 墨 | 0.945 0.008 85 | #efece7 | 0.235 0.010 70 | #211d19 |
| `--primary-foreground` | （作業台と同じ） | 0.255 0.006 75 | #252220 | 0.925 0.004 75 | #e8e6e3 |
| `--muted-foreground` | 鉛筆 | 0.775 0.008 75 | #b9b5b0 | 0.445 0.010 75 | #57534e |
| `--border` | 罫 | 0.405 0.007 75 | #4b4945 | 0.855 0.005 75 | #d1cfcc |
| `--input` | 縁 | 0.585 0.008 75 | #7f7b77 | 0.585 0.008 75 | #7f7b77 |
| `--destructive` | （CRITICAL の塗り） | 0.560 0.200 26 | #d02c2e | 0.540 0.205 27 | #cb1e21 |
| `--signed` | 紫印 | 0.815 0.105 305 | #d2b1f9 | 0.480 0.170 302 | #713dab |

コントラスト（`scripts/palette.py` で計算。WCAG 2.1 の相対輝度）:

| 組み合わせ | ダーク | ライト | 基準 |
|---|---|---|---|
| 墨 / 作業台 | 13.42 | 13.44 | 4.5 |
| 墨 / 台紙 | 11.81 | 16.48 | 4.5 |
| 墨 / 浮き | 10.19 | 16.74 | 4.5 |
| 墨 / 選択行 | 9.44 | 14.22 | 4.5 |
| 鉛筆 / 作業台 | 7.75 | 6.12 | 4.5 |
| 鉛筆 / 台紙 | 6.83 | 7.51 | 4.5 |
| 鉛筆 / 浮き | 5.89 | 7.63 | 4.5 |
| 鉛筆 / 選択行 | 5.46 | 6.48 | 4.5 |
| 主ボタン（作業台色の文字 / 墨の塗り） | 13.42 | 13.44 | 4.5 |
| 縁 / 作業台（入力欄の枠、1.4.11） | 3.77 | 3.37 | 3.0 |
| 縁 / 台紙 | 3.32 | 4.13 | 3.0 |
| 縁 / 凹み | 4.09 | 3.69 | 3.0 |
| フォーカス（墨）/ 作業台 | 13.42 | 13.44 | 3.0 |
| ワードマーク / 作業台 | 14.52（#F5F5F7） | 13.51（#1D1D1F） | 4.5 |
| 罫 / 台紙 | 飾りなので対象外。部品の境界は縁（edge）で示す | | |

### 5.3 重大度トークン

各重大度に `--{sev}`（文字とアイコンと帯）、`--{sev}-tint`（淡色地）、`--{sev}-solid`（塗り）、`--{sev}-solid-fg` の 4 つ。`@theme inline` で `--color-critical` などにマップする。**変数名 `safe` は現行と同じ**にする（E2E の `.text-safe, .bg-safe` の検査がそのまま意味を持つ）。

文字色のコントラスト（`palette.json`。基準 4.5）:

| 重大度 | 形（lucide） | ダーク 文字 | 淡色地 | 作業台 | 台紙 | 浮き | 選択行 | ライト 文字 | 淡色地 | 作業台 | 台紙 | 浮き | 選択行 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CRITICAL | octagon-alert | #fe938d | 5.85 | 7.36 | 6.48 | 5.59 | 5.18 | #b21a1c | 6.01 | 5.51 | 6.76 | 6.87 | 5.83 |
| HIGH | triangle-alert | #fdb171 | 6.92 | 8.81 | 7.76 | 6.69 | 6.20 | #9e480f | 5.50 | 4.98 | 6.10 | 6.20 | 5.26 |
| MEDIUM | circle-alert | #f3d761 | 8.56 | 11.07 | 9.75 | 8.40 | 7.79 | #79570b | 5.94 | 5.30 | 6.50 | 6.60 | 5.61 |
| LOW | diamond | #89c8fe | 6.78 | 8.85 | 7.79 | 6.72 | 6.23 | #0b5bae | 5.91 | 5.40 | 6.62 | 6.73 | 5.71 |
| INFO | info | #c8c3bd | 6.56 | 9.03 | 7.95 | 6.86 | 6.36 | #5a5651 | 6.29 | 5.84 | 7.17 | 7.28 | 6.18 |
| SAFE | circle-check | #7ee09b | 7.67 | 9.80 | 8.63 | 7.44 | 6.90 | #1b6c3a | 5.77 | 5.18 | 6.35 | 6.46 | 5.48 |
| L3（紫印） | なし（二重枠） | #d2b1f9 | 6.72 | 8.58 | 7.56 | 6.51 | 6.04 | #713dab | 6.26 | 5.70 | 6.99 | 7.10 | 6.03 |

- 最小はライトの HIGH / 作業台の **4.98:1**。HIGH の文字を作業台に直接置くのは欄外の注記だけで、一覧と集計は台紙の上（6.10）。
- 淡色地の hex（ダーク / ライト）: CRITICAL #562422 / #fdecea、HIGH #4c2d13 / #feefe1、MEDIUM #3d3515 / #fcf3d1、LOW #1d3850 / #e9f1fc、INFO #3c3935 / #f0eeeb、SAFE #1b3b25 / #e1f8e6、L3 #3f2c53 / #f4eefe。
- 塗り（SkillPact の「未宣言」のピルだけで使う）: CRITICAL はダーク #d02c2e に #fcfcfc で **5.01:1**、ライト #cb1e21 に #fcfcfc で **5.46:1**。
- 各色相の距離: 赤 24〜27、橙 48〜60、黄 80〜96、青 245〜255、紫 302〜305、緑 150〜152、灰は彩度 0.01。色覚の違いに備えて、**形（八角形、三角、円、菱形、i、チェック、二重枠）と語を必ず併記する**。色だけで区別する箇所はない。

**L3 の規則（C-10）**
- L3 の表示は紫印（`--signed` の二重枠。外枠 1.5px、内枠 0.75px、角丸 2）だけ。文言は「L3 署名済みファイル」に固定。
- 緑（`--safe`）、ティール、主色（墨）は L3 に使わない。チェック形のアイコン（circle-check、badge-check、shield-check）も使わない。「安全」「信頼」「Verified」とも書かない。
- 押印の隣には必ず意味の文を置く（「L3 は『署名済みファイル』であることのみを示し、安全性や作者の信頼性を意味しません」）。ツールチップに隠さない。
- SkillPact のタブパネルには `--safe` の部品を一つも置かない（既存の E2E を維持）。

### 5.4 CSS の骨組み（実装時の形。いまは書かない）

```css
@import "tailwindcss";
@import "tw-animate-css";

/* 既定はダーク（N-03）。.light で明示的にライト、.dark で明示的にダーク。
   クラスが無いときは OS の設定に従う（スクリプトが動く前にちらつかない） */
:root { color-scheme: dark;
  --background: oklch(0.255 0.006 75); --card: oklch(0.295 0.006 75); --popover: oklch(0.335 0.007 75);
  --muted: oklch(0.225 0.006 75); --accent: oklch(0.355 0.007 75);
  --foreground: oklch(0.945 0.008 85); --primary: var(--foreground); --ring: var(--foreground);
  --primary-foreground: var(--background); --muted-foreground: oklch(0.775 0.008 75);
  --border: oklch(0.405 0.007 75); --input: oklch(0.585 0.008 75);
  --signed: oklch(0.815 0.105 305); /* … 重大度 7 種 × 4 … */ }
@media (prefers-color-scheme: light) { :root:not(.dark) { color-scheme: light; /* … ライトの値 … */ } }
:root.light { color-scheme: light; /* … ライトの値 … */ }

@custom-variant dark (&:where(:root:not(.light) *));

@theme inline {
  --color-background: var(--background); /* … shadcn の全トークン … */
  --color-critical: var(--critical); --color-critical-tint: var(--critical-tint); /* … */
  /* 角丸は役割ごと。shadcn の --radius からの計算はやめる */
  --radius-xs: 2px;   /* 押印 */
  --radius-sm: 3px;   /* タグ、件数 */
  --radius-md: 4px;   /* 台紙、行のハイライト */
  --radius-lg: 6px;   /* ボタン、入力欄、トースト */
  --radius-2xl: 14px; /* 下からのシートの上端 */
  --font-sans: system-ui, -apple-system, "Segoe UI", "Hiragino Sans", "Hiragino Kaku Gothic ProN", "Noto Sans JP", "Yu Gothic UI", "Yu Gothic", Meiryo, sans-serif;
  --font-mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Cascadia Mono", "Noto Sans Mono", "Hiragino Sans", "Noto Sans JP", monospace;
}

/* フォーカス: 墨の輪郭。色相を持たないので、重大度の地の上でも意味がぶつからない */
:where(button, a, input, textarea, select, [tabindex]):focus-visible { outline: 2px solid var(--ring); outline-offset: 2px; }

@media (prefers-reduced-motion: reduce) { *, ::before, ::after { animation-duration: 0ms !important; transition-duration: 0ms !important; } }
```
- テーマ切替は「ダーク / ライト / システム」の 3 択（ghost のアイコンボタン＋Tooltip）。保存先は localStorage の `zes-theme`（try/catch で包み、失敗したら保存せずに動かす）。描画前にクラスを付けるための別のインラインスクリプトは作らない（CSP のハッシュが 2 つになるため）。
- 等幅の和文フォールバックに Hiragino Sans と Noto Sans JP を足したのは、パスに日本語が入ったときに明朝へ落ちないようにするため。

---

## 6. タイポグラフィ

- **Web フォントは同梱しない**（C-02、`font-src 'none'` のまま）。`--font-sans` と `--font-mono` は §5.4。macOS / iOS では SF＋ヒラギノ角ゴ、Windows では Segoe UI＋Yu Gothic UI、Android / Linux では Roboto か Noto Sans JP になる。
  - Inter を同梱しない理由（v0.1 から変更なし）: latin のサブセットでも 1 ウェイトあたり 60〜100 KiB（base64）増え、`font-src data:` への CSP 変更が要る。日本語には効かない。
  - ブランドの書体（Inter Display SemiBold）は**ワードマークの SVG（アウトライン化済み）でだけ**使う。
  - モックアップは環境の都合で Inter、IPA Pゴシック、JetBrains Mono で描いた。実際の表示ではヒラギノや Noto になる。
- **2 書体の役割**
  - 和文・UI（system-ui）: 見出し、本文、ボタン、ラベル、件数、版、§番号、ルール番号。数字は `tabular-nums`。
  - コード（ui-monospace）: パス、コマンド、bundle ID、エフェクト名（`exec`、`network` など）、ハッシュ。**端末に打ち込める文字列だけ**。
- **組み方そのものを設計にする箇所**: パスはディレクトリを鉛筆、ファイル名を墨の 500 にする（`chaindrop/` + `package-lock.json`）。どのファイルかが一目で分かり、同じディレクトリが続いても読み飛ばせる。検体票のパスは等幅 26px の 600。
- 段階（『The Elements of Typographic Style』の伝統的な段階 12 / 14 / 16 / 18 / 21 / 24 から取り、検体票だけ 26）:

  | 用途 | サイズ | 行間 | ウェイト |
  |---|---|---|---|
  | 検体票のパス | 26（スマホ 22）、等幅 | 1.2 | 600 |
  | 画面の見出し（スキル名） | 21〜22 | 1.35 | 600 |
  | 集計の数字 | 21（スマホ 19） | 1 | 600、`tabular-nums` |
  | 台紙と節の見出し | 15〜16 | 1.5 | 600 |
  | 本文、ボタン、タブ、入力、一覧のパス（等幅 14） | 14 | 1.5（説明文は 1.7） | 400 / 500 |
  | 一覧の詳細、表の本文 | 12.5〜13 | 1.5 | 400 |
  | 補足、タグ、書式のラベル | 12 | 1.4 | 400 / 500 |
- 日本語は最小 12px。字間は 0。**英大文字（重大度の値）にも字間を付けない**。
- 1 行の長さ: 説明文は 1 行 40 字（約 520px）を超えないように欄の幅を決める。欄外は 320px（約 24 字）。
- 折り返し: 見出しとボタンは `word-break: auto-phrase`（Chromium 119 以降）と `text-wrap: balance`。本文は `line-break: strict`。パスとコマンドは `overflow-wrap: anywhere`。一覧では 1 行で切り、全文は Tooltip（デスクトップ）か詳細シート（モバイル）とコピーで取れるようにする。
- 約物: 全角の括弧（（））と中黒（和語の並列だけ）。英数字と和文の間は半角スペース（`2 MiB 超`）。付帯情報を中黒でつながない（A-8）。
- `font-feature-settings: "palt"` は使わない（v0.1 から変更なし）。

---

## 7. 余白・形状・影・モーション

- 4px グリッド。主な値: 4 / 8 / 12 / 16 / 20 / 24 / 32。ページの左右の余白は ≥1024px で 24px、<1024px で 16px。主列と欄外の間は 32px。
- **角丸は役割ごと**（A-3）: 押印 2、タグと件数 3、台紙と行のハイライト 4、ボタン・入力欄・トースト 6、下からのシートの上端 14。
- **台紙は 3 枚だけ**（検体票、検出一覧、SkillPact の報告）。台紙の枠は罫 1px。それ以外（集計、欄外の注記、スキルの一覧）は作業台に直接置く。集計は罫の枠だけで塗らない。
- **影**: 浮くものだけ（ポップオーバー、下からのシート、トースト、Tooltip）。ダークは `0 6px 18px rgb(0 0 0 / .45)`、ライトは `/ .16`。台紙には影を付けない。
- 高さ: ボタンと入力は 36px、小さいボタンは 30〜32px。**タッチ環境（`pointer: coarse`）では 44px**（モバイルのモックアップはすべて 44px）。
- 破線: 1〜1.5px、`4 4`。ドロップ先、該当なし、判定不可、前版との差分比較の案内だけ。
- 罫: 表の行、書式の欄、欄外の節の区切り。欄外の未判定の内訳だけ点線（`2 3`）。
- **モーション**: 自動で動くものは置かない。操作への応答だけ。
  - 下からのシート: 180ms、`translateY` のみ。
  - ポップオーバーとタブ検索: 120ms のフェードのみ（ズームはしない）。
  - Tooltip: 遅延 400ms、フェード 80ms。
  - スキャン中の表示は回転やパルスにせず、件数の数字で進捗を出す。
  - `prefers-reduced-motion: reduce` ではすべて 0ms（§5.4）。

---

## 8. レイアウトとブレークポイント

### 8.1 案の比較（ASCII）

**A. v0.1 の骨組み**（比較用。不採用）: カードの縦積み。サマリの大きな数字とフィルタが二重。
```
┌ヘッダー───────────────────────────────────────────────┐
├タブ ‹ … › [すべてのタブ]──────────────────────────────┤
│┌入力カード（ドロップ｜貼り付け）────────┐ ┌Blast Radius┐│
│└──────────────────────────┘ └──────┘│
│ スキャン完了 ・ 4 ファイル ・ 0.0 秒          ┌CLI────┐│
│┌CRIT 4┐┌HIGH 3┐┌MED 0┐┌SAFE 62┐       └──────┘│
│(CRIT 4)(HIGH 3)(MED 0)(LOW 0)(INFO 0) [検索][▼] ┌未判定─┐│
│┌表────────────────────────┐ └──────┘│
```

**B. 検疫台（採用）**: 台紙は「読む対象」だけ。道具は作業台の上。左寄せ。
```
┌ロゴ  v0.1.0  ZES-2026-OCT-…      [オフライン・外部通信ゼロ] 読み込む [JSON 出力] クリア ◐┐
├総合 7  SkillPact  TeamPCP  ChainDrop 5  …                         [⌕ すべてのタブ 18]┤
│┌検体票（台紙）─────────────────────────────────┐   テキスト貼り付け判定      │
││検体          │ファイル│判定時間│未判定│実行 │✓ スキャン完了  [フォルダを選択…]││  ┌凹み──────────┐ │
││chaindrop/    │ 4    │0.0 秒 │0 件 │0 回 │ドロップで差し替え          ││  └──────────────┘ │
│└─────────────────────────────────────────┘   0 / 1,000,000  [判定する]│
│┌集計＝フィルタ（罫の枠だけ）───────────┐ ✓ 62 / 67 チェック非該当   ───────────────── │
││▌4 ✓│▌3 ✓│ 0 □│ 0 □│ 0 □│  ブラウザで判定できる範囲のみ Blast Radius [存在のみ]│
││CRIT│HIGH │MED │LOW │INFO│                           ┆該当なし┆           │
│└────────────────────┘                               ───────────────── │
│┌検出一覧（台紙）──────────── [⌕ 検索      ] [モジュール ▼]┐   ホスト検査は CLI で実施  │
││溝│重大度   │パス / 詳細                      │キャンペーン │§  │⧉│   ┌./zes-scan.sh …┐ │
││▌ │⬣ CRITICAL│chaindrop/package-lock.json      │chaindrop-keyv│§15│⧉│   └───────────┘ │
││▌ │          │侵害パッケージ keyv@6.0.0 を検出    │             │   │ │  ───────────────── │
││▌ │▲ HIGH    │chaindrop/setup.mjs              │…            │§15│⧉│   未判定（0 件扱いしない）│
```
- 左右とも左揃え。数値だけ右揃え（欄外の未判定の件数）。中央揃えは空の状態のドロップ先とエフェクト表の列だけ。
- 主列 1fr（1440 幅で 1040px）、欄外 320px、間 32px。

**C. 空の状態（スキャン前）**: 検体票の位置に大きなドロップ先（破線、中央揃え）。
```
│┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐   テキスト貼り付け判定 │
│        フォルダをドロップして判定                              ┌──────────┐ │
│   内容は判定にのみ使い、表示・保存・送信しません                 └──────────┘ │
│            [フォルダを選択…]   findings.json を読み込む                         │
│└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘                         │
```

**D. モバイル（375）**
```
┌▣ zero-exec shield        ◐ [⋯]┐
├総合 7 SkillPact TeamPCP Cha [⌕]┤
│┌検体───────── ✓ スキャン完了┐│
││chaindrop/                    ││
││ファイル│判定時間│未判定│実行  ││
││4      │0.0 秒 │0 件 │0 回  ││
│└───────────────┘│
│[フォルダを選択…          ] [📋]│
│┌▌4 ✓  │▌3 ✓  │ 0 □   ┐   │
││CRIT  │HIGH  │MED    │   │
││ 0 □  │ 0 □  │✓62/67 │   │
│└───────────────┘│
│[⌕ パス・キャンペーンで検索] [≡]│
│┌───────────────┐│
││▌⬣ CRITICAL §15　chaindrop-keyv││
││▌chaindrop/package-lock.json [⧉]││
││▌侵害パッケージ keyv@6.0.0 を…  ││
```

### 8.2 ブレークポイント

| 幅 | ヘッダー | タブ | 主列 | 欄外 | 検出一覧 |
|---|---|---|---|---|---|
| ≥1280（基準 1440、`overview-*.svg`） | 56px・1 段 | 44px。収まるタブだけ出し、右端に「すべてのタブ 18」 | 検体票（5 欄＋操作）、集計 5 区画＋SAFE の文、一覧 | 右 320px | 表（溝＋重大度 128 / パス 1fr / キャンペーン 160 / モジュール 72 / コピー 48） |
| 1024–1279 | bundle ID は Tooltip に入れる | 同じ | 検体票は「未判定」「実行」を 2 段目へ | 右 300px | キャンペーン 128 |
| 768–1023 | 操作は「JSON 出力」と「…」 | 同じ | 1 列 | 一覧の下に 2 列で並べる | 表 |
| 640–767 | 同じ | 横スクロールのみ | 1 列。集計は 5 区画のまま | 1 列 | 表（モジュール列を消し、キャンペーンの下に出す） |
| <640（基準 375、`mobile-*.svg`） | 52px: マーク＋ワードマーク、テーマ、「…」（44px） | 44px の横スクロール＋右端に検索ボタン（44px）→ 下からのシート | 検体票は 2 段（パス／4 欄）。集計は 3＋2 区画＋SAFE。ボタンは 44px | 1 列（一覧の下） | 1 件 96px の行（§10.4） |
| 320–359 | ワードマークを消してマークだけ | 同じ | **集計は 2 列×3 段**（1 区画 144px。3 列の 96px ではチェックと「CRITICAL」が重なるため）。検体票の 4 欄は 72px（「判定時間」と「0.0 秒」が収まる） | 同じ | 同じ |

- どの幅でもページは横にスクロールしない。横スクロールするのは「タブの列」と「SkillPact のエフェクト表（<768px）」だけ。
- 仮想スクロールは行の高さを固定にする方式のまま。表は 60px、カード型の行は 96px。`matchMedia('(min-width: 640px)')` で切り替える。

---

## 9. コンポーネント対応表

shadcn new-york-v4 のソースを手で取り込み（承認済み §16-6）、**見た目のクラスは「検疫台」に合わせて書き換える**。「CSP」列: ✅ は実測で違反ゼロ、— は Radix を使わない。「サイズ」は §4.3 の単体の増分（min）。

| 現在（[`ui/src/components`](../../ui/src/components/)） | 置き換え先 | 依存 | CSP | サイズ | 見た目（shadcn の既定から変える点） | a11y・テスト |
|---|---|---|---|---|---|---|
| `ui.tsx` の `Button` | **Button**（`ink` / `outline` / `ghost` / `icon` の 4 種。shadcn の `secondary` と `link` は使わない） | cva、@radix-ui/react-slot | ✅ | 約 1 KiB | 角丸 6。`ink` は墨の塗りに作業台色の文字。disabled は罫の枠と鉛筆色（不透明度で薄めない） | アイコンだけのボタンは `aria-label` 必須。36px、タッチでは 44px |
| `ui.tsx` の `Card` | **Card は「台紙」専用**（検体票、検出一覧、SkillPact の報告）。欄外は `<section>` | なし | — | 0 | 角丸 4、罫 1px、影なし、内側の余白 20 | `data-testid` は維持 |
| `ui.tsx` の `SeverityBadge` と `Pill` | **Badge を 3 つの部品に分ける**: `SeverityMark`（溝の印。形＋語、枠なし）、`SeverityTag`（淡色地、角丸 3）、`Tag`（無彩色、罫の枠） | cva | — | 0 | ピルにしない。字間 0 | `data-severity` を維持 |
| （新規）押印 | **`Stamp`**（L3 の紫印。二重枠） | なし | — | 0 | 外枠 1.5px、内枠 0.75px、角丸 2、紫印の文字 600 | `data-testid=l3-badge` |
| `ui.tsx` の `Icon` | **lucide-react**（v0.1 の一覧のとおり）＋ブランドのロゴ SVG | lucide-react | — | 約 0.5 KiB／個 | 線幅 2〜2.25 | `aria-hidden` |
| `ui.tsx` の `ToastProvider` | **自作のトーストを残す**（承認済み §16-7） | なし | — | 0 | 浮きの地、罫、角丸 6、影。主列の右下 | `role="status" aria-live="polite"` を維持 |
| `ui.tsx` の `ErrorBoundary` | **Alert**（destructive）＋ Button | なし | — | 0 | 台紙に CRITICAL の帯 | `role="alert"`、`data-testid=render-error` |
| `layout.tsx` の `Header` | ロゴ SVG、`Tag`、Button、Tooltip、モバイルは **DropdownMenu** | @radix-ui/react-tooltip、react-dropdown-menu | ✅（互換モジュールが要る） | 56.9 / 95.1 | Separator は使わず、間隔で区切る | `<h1>` はロゴを包み `aria-label="zero-exec shield"`。`data-testid=bundle` |
| `layout.tsx` の `TabBar` | **Tabs**（`activationMode="manual"`、`loop`）。左右の矢印ボタンはやめる | @radix-ui/react-tabs | ✅ | 28.3 | 選択中は墨の 600＋2px の墨の線。件数は淡色地の数字 | ←→ / Home / End / Enter の E2E を維持。件数は `aria-label` に含める |
| 「すべてのタブ」 | ≥640: **Popover＋Command**。<640: **Sheet（下）＋Command** | react-popover、react-dialog、cmdk | ✅（互換モジュールが要る） | 70.0 / 52.0 | 浮きの地、角丸 6（シートは上端 14）。選択中は選択行の地＋墨の帯＋チェック | combobox / listbox / option（§14）。IME 変換中の Enter を無視 |
| `overview.tsx` の `InputArea` | スキャン前: 大きなドロップ先（破線）。スキャン後: **検体票**（Card）。貼り付けは欄外の `<section>`＋Textarea | なし | — | 0 | §10.3 | `data-testid` の dropzone / dir-input / import-input / paste / paste-submit を維持。dropzone は検体票全体に付け、dragover で破線の縁を出す |
| `SummaryCards` ＋ `FindingsToolbar` の重大度チップ | **集計（ToggleGroup `type="multiple"`）に統合** | @radix-ui/react-toggle-group | ✅ | 26.1 | 罫の枠だけ。押した区画は左に 3px の帯＋チェック＋色。押していない区画は鉛筆色＋空の枠 | 区画に `data-testid=filter-{SEV}`、数字に `count-{SEV}`。`card-*` は廃止（E2E は参照していない。§14） |
| `FindingsToolbar` の検索とモジュール | **Input**＋**Native Select**。検出一覧の台紙の見出し行に置く | なし | — | 0 | 凹みの地、縁の枠、角丸 6 | `data-testid=search` |
| `FindingsTable` | 自作の仮想スクロール＋ shadcn Table の構造 | なし | — | 0 | 行 60px。左端 4px の重大度の帯、溝に `SeverityMark`、パスは 2 色の等幅。hover は選択行の地 | 見出し行を `role="table"` の中に（W-8）。`aria-rowcount` / `aria-rowindex` |
| `BlastRadiusPanel`、`CliOnlyNotice`、`UndeterminedCard` | 欄外の `<section>`（見出し＋本文）。空は破線 | なし | — | 0 | 見出しの前のアイコンはなし。コマンドは凹みの欄 | `data-testid` を維持 |
| `skillpact.tsx` の L3 の注記 | 報告の見出しの中で、**押印の右に常に表示** | なし | — | 0 | 全幅の紫の帯はやめる | `data-testid=l3-note` |
| `SkillList` | 作業台の上のリスト。選択中だけ台紙の地＋左に墨の帯 | なし | — | 0 | | `data-testid=skill-item`、`aria-pressed` |
| `SkillPactViewer` | **報告**（1 枚の台紙を罫で節に分ける） | なし | — | 0 | 事実はラベルと値の組。ポリシーは MEDIUM のタグ | `data-testid=skillpact-viewer` |
| `EffectMatrix` | ネイティブの `<table>`。書式なので全セルに罫 | なし | — | 0 | 見出し行は凹みの地。宣言は墨の枠、未宣言の実態は CRITICAL の塗り | `td[data-effect][data-divergence]` を維持 |
| prose / diff の Alert | **溝の帯の行**（検出一覧と同じ形）。判定不可は破線の帯と鉛筆色 | なし | — | 0 | 色付きの枠のカードにしない | `data-testid` の prose-alert / diff-alert |
| ルールの一覧 | `<ol>` の 2 列。該当は CRITICAL の淡色地＋帯 | なし | — | 0 | 番号は 0 埋めしない | `data-testid=rule-row`、`data-status` |
| `viewers.tsx`（MCP / Actions / 拡張） | 台紙 1 枚＋行の一覧（`divide-y`） | なし | — | 0 | 値は凹みの `<code>`。危険なトークンは `SeverityTag` | `data-risk`、`data-kind` |
| 不採用 | Sonner、Select、ScrollArea、Data Table、Resizable、Sidebar | — | — | — | 理由は §4.2 と §4.3 | |

---

## 10. 画面別の仕様（モックアップとの対応）

### 10.1 ヘッダー（`overview-*.svg` の 0〜56px）
- 左: ロゴ（高さ 28px、[`zes-logo-dark.svg`](../../brand/logo/zes-logo-dark.svg) / [`-light.svg`](../../brand/logo/zes-logo-light.svg)）、版「v0.1.0」（12px、鉛筆。Tooltip「準拠仕様 v5.2」）、bundle ID `ZES-2026-OCT-EMERGENCY-V5.2`（等幅 13px、鉛筆。ピルにしない）。
- 右: `Tag`（wifi-off）「オフライン・外部通信ゼロ」（無彩色。Tooltip で CSP の説明）、ghost「findings.json を読み込む」、outline「JSON 出力」（スキャン前は disabled）、ghost「クリア」、テーマ（ghost のアイコン）。
- 下に罫 1px。ヘッダーは作業台と同じ地（塗り分けない）。
- <640: マーク（28px）＋ワードマーク（高さ 14.5px）、テーマ、「…」（DropdownMenu: JSON 出力 / findings.json を読み込む / クリア / テーマ / bundle ID の表示とコピー）。

### 10.2 タブ（56〜100px）
- 選択中: 墨の 600、下に 2px の墨の線。それ以外: 鉛筆の 500、hover で墨。
- 件数: 最大の重大度の淡色地に、その文字色の数字（12px の 600、角丸 3）。0 件なら出さない。
- デスクトップは**収まるタブだけ**を出す（はみ出す分は描かない。グラデーションのフェードも矢印ボタンも使わない）。右端の outline「⌕ すべてのタブ 18」→ Popover（幅 360、最大 70vh）: Command の入力欄「タブを検索（例: mcp, 永続化）」、18 件（36px、選択中は選択行の地＋墨の帯＋チェック、右に件数）。
- <640: 右端の検索ボタン（44px）→ 下からのシート（`mobile-menu-dark.svg`）: つまみ、「すべてのタブ 18」、閉じる（44px）、検索欄（フォーカスの輪郭）、「並びは §7.2 の順で固定。数字は検出件数です。」、1 件 44px のリスト。**検出 0 件のタブには数字を出さない**。

### 10.3 総合タブ・デスクトップ（`overview-dark.svg` / `overview-light.svg`）
- **検体票**（y=124、高さ 88、台紙）: 「検体」（12px 鉛筆）と `chaindrop/`（等幅 26px）｜ファイル 4｜判定時間 0.0 秒｜未判定 0 件｜実行 0 回｜✓ スキャン完了・ドロップで差し替え｜墨の「フォルダを選択…」。欄の間は点線の罫。`data-testid=scan-status` は「スキャン完了」の欄に付ける（E2E の `toContainText('スキャン完了')` を満たす）。
  - 「実行 0 回」は常に 0 だが、製品の約束を記録として書く欄。Tooltip で「ZES はファイルを実行・インストールしません」。
  - 検体名は投入したフォルダの最上位の名前（`webkitRelativePath` の先頭）。貼り付け判定だけのときは「貼り付けたテキスト」、findings.json のときはそのファイル名。
- **集計＝重大度フィルタ**（y=232、高さ 64）: 5 区画（150px）。区画の中は数字（21px、墨）と、形＋語（12px）。押した区画は左 3px の帯＋右上のチェック＋語とアイコンを重大度の色に。押していない区画は鉛筆色＋右上に空の枠。右に「✓ 62 / 67 チェック非該当」「ブラウザで判定できる範囲のみ」（SAFE の緑はアイコンだけ）。
- **検出一覧**（y=312〜、台紙）: 見出し行に「検出 7 件」、検索（300px）、モジュール（176px）。列見出しは 12px の鉛筆。行は 60px: 左端 4px の帯、溝に形＋語、パス（等幅 14、ディレクトリは鉛筆）と詳細（12.5、鉛筆）、キャンペーン、モジュール、コピー（ghost 32px）。hover は選択行の地。コピーの Tooltip は左側に出す（モジュールの列に掛からない位置）。モックアップの 2 行目は hover とキーボードのフォーカス（墨の輪郭）の見本。
- **欄外**（x=1096、幅 320）: 
  1. テキスト貼り付け判定: 見出し、検出の対象（「C2 ドメイン/IP・base64・exec(・curl」）、Textarea（凹み、84px）、文字数、outline の「判定する」（空なら disabled）。
  2. Blast Radius＋`Tag`「存在のみ・内容非表示」、説明、空は破線の「該当なし（投入フォルダ内のみ判定）」、件数の注記、「パス一覧をコピー」、手順。
  3. ホスト検査は CLI で実施: 説明 3 行、コマンドの凹みの欄＋コピー。
  4. 未判定（0 件扱いしない）: 4 行の内訳。行の間は点線の罫、件数は右揃え。
- トースト: 主列の右下。浮きの地、check、「パスをコピーしました」、閉じる。

### 10.4 総合タブ・モバイル（`mobile-overview-*.svg`）
- 検体票（2 段）: 上段に「検体」と `chaindrop/`（等幅 22px）と「✓ スキャン完了」、下段に 4 欄。
- 墨の「フォルダを選択…」（44px）と clipboard のボタン（44px。下からのシートで貼り付け欄を開く）。
- 集計 3＋2 区画（56px）と SAFE の文。320〜359px は 2 列×3 段。
- 検索（44px）とフィルタのボタン（モジュール選択をシートで開く）。
- 検出: 1 件 96px。左端の帯、1 行目は形＋語と「§15　chaindrop-keyv」（全角スペースで区切る）、2 行目にパス（等幅 13.5、1 行で切る）、3 行目に詳細（12px、1 行で切る）、右にコピー（44px）。
- **行を押すと詳細のシート**（承認済み §16-5）: 浮きの地、上端 14。見出しに帯と形＋語、パスの全文（等幅、折り返す）、詳細の全文、キャンペーン、モジュール、「パスをコピー」（墨、44px）。閉じるとフォーカスは押した行に戻る。

### 10.5 SkillPact タブ（`skillpact-dark.svg` / `skillpact-light.svg`）
- 左の列（296px、作業台の上）: 「スキル 1 件」、説明、絞り込み（スキルが 5 件以上のとき）。選択中の項目は台紙の地＋左に墨の帯。項目には押印（小）と `CRITICAL 3`。破線の「前版との差分比較」。下に「SAFE 表示は使用しません（安全の断定をしない）」。
- 右は**報告（台紙 1 枚）**。罫で 4 節に分ける。
  1. 見出し: スキル名（22px）、契約のパス（等幅）、右上に `CRITICAL 3`。事実はラベルと値の組（author / version / L2 記録 / 署名ファイル / 契約 / ポリシー）。ポリシーの値「ask」は MEDIUM のタグ。押印「L3 署名済みファイル」と、その右に意味の文（墨）と「契約は JSON パースのみ。スキル・L2 テスト・署名検証は実行しません」（鉛筆）。
  2. エフェクト：宣言（契約） vs 実態（静的解析）。凡例（未宣言＝CRITICAL の塗り、宣言あり＝墨の枠、— なし）。全セルに罫のある書式。宣言は墨の枠のピル、未宣言の実態は CRITICAL の塗りのピル、宣言済みの実態は墨の文字、差分は「⬣ 未宣言・CRITICAL」か「一致」。
  3. 2 件の指摘を溝の帯の行で: 「HIGH prose と契約の矛盾」（HIGH の帯）、「判定不可 差分異常」（破線の帯、鉛筆色。色で安心させない）。
  4. §49 検出ルール: 「12 ルール：該当 3、非該当・対象外 8、判定不可 1」。2 列 6 段。該当の行は CRITICAL の淡色地＋帯、状態の語は CRITICAL の 600。

### 10.6 MCP / GitHub Actions / ブラウザ拡張（モックアップなし）
- 各ビューアは台紙 1 枚。中は「パス（等幅、ディレクトリは鉛筆）」と行の一覧。値は凹みの `<code>`。危険なトークンは `SeverityTag`。
- Actions の参照の種類: SHA 固定 = SAFE のタグ（旧設計書 §8.6 の承認済みの方針を維持）、タグ参照 = HIGH、汚染の可能性 = CRITICAL、ローカル = 無彩色の `Tag`。
- 空は破線と文言（「0 件 ＝ 安全」と読めない書き方。現行の文言を維持）。読み込み中は件数の進捗を文字で出す。エラーは Alert（destructive）。

### 10.7 文言の変更一覧

方針: 現行の日本語は残す。変えたのは、スキルの文章の指針（利用者の言葉で書く、1 つの要素は 1 つの役目、同じ操作は同じ名前、付帯情報を中黒でつながない）で明らかに良くなる箇所だけ。

| # | 場所 | 現行 | v0.2 | 理由 |
|---|---|---|---|---|
| T-1 | 状態の行 | 「スキャン完了 ・ 4 ファイル ・ 0.0 秒」 | 検体票の欄「ファイル 4」「判定時間 0.0 秒」と「スキャン完了」 | 中黒の付帯情報（A-8）を書式の欄にした。「スキャン完了」の語は残す（E2E） |
| T-2 | 状態の行 | 「未判定 0 件（サイズ超過 0 / バイナリ 0 / リンク先不明 0）→ 右パネル参照」 | 検体票の「未判定 0 件」。内訳は欄外 | 「→ 右パネル参照」（A-10）を削除。内訳は欄外にあり、二重に書かない |
| T-3 | 検体票（新規） | — | 「検体」「ファイル」「判定時間」「未判定」「実行」「0 回」「ドロップで差し替え」 | 新しい書式の欄名 |
| T-4 | ドロップ領域 | 「フォルダをドラッグ＆ドロップ」「または フォルダを選択… webkitdirectory」 | 「フォルダをドロップして判定」「フォルダを選択…」 | 動作を言い切る。`webkitdirectory` は利用者に関係のない実装名 |
| T-5 | ドロップ領域の注記 | 「ファイル内容は判定にのみ使用し、画面表示・保存・送信を行いません。」 | 「内容は判定にのみ使い、表示・保存・送信しません」 | 意味は同じで短い（W-4 の折り返し対策）。「1 ファイル 2 MiB 超は未判定として計上」は欄外の未判定の内訳「サイズ超過（2 MiB 超）」に任せる |
| T-6 | サマリカード | 「クリックで絞込（選択中）」「LOW 0 ・ INFO 0 を含みます」 | なし | 押した状態はチェックと帯で示す。「含みます」は MEDIUM の数に LOW と INFO が入っているように読めた（実際は別々）。集計に LOW と INFO の区画ができたので不要 |
| T-7 | SAFE のカード | 見出し「SAFE」、「62 / 67 チェック非該当」「ブラウザ判定範囲のみ」 | 「62 / 67 チェック非該当」「ブラウザで判定できる範囲のみ」 | 「SAFE」を大きな見出しにすると「62 件安全」と読める。事実（非該当の数）だけを書く |
| T-8 | ツールバー | 「重大度」のラベル | なし | 集計の区画そのものが重大度なので、上のラベルは不要（A-7） |
| T-9 | トースト | 「パスをクリップボードにコピーしました」 | 「パスをコピーしました」 | ボタンの名前「パスをコピー」と揃える（同じ操作は同じ名前） |
| T-10 | タブ検索の注記（v0.1 で新規） | 「§7.2 の順序（固定）・数字は検出件数」 | 「並びは §7.2 の順で固定。数字は検出件数です。」 | 中黒の付帯情報を文にした |
| T-11 | SkillPact の見出し | 「author: trusted-vendor ・ version 3.0.0」「L2 記録: なし ・ 署名ファイル: あり（検証は未実行）」 | ラベルと値の組（author / version / L2 記録 / 署名ファイル / 契約 / ポリシー） | A-8 |
| T-12 | SkillPact のバッジ | 「契約あり・v0.8」「ポリシー: ask」 | 事実の欄「契約 あり（v0.8）」「ポリシー ask」 | 同上 |
| T-13 | §49 の集計 | 「12 ルール・該当 3・非該当/対象外 8・判定不可 1」 | 「12 ルール：該当 3、非該当・対象外 8、判定不可 1」 | 中黒の連結を読点に |
| T-14 | L3 の注記の補足 | 「契約は JSON パースのみ・スキル / L2 テスト / 署名検証は実行しません」（v0.1） | 「契約は JSON パースのみ。スキル・L2 テスト・署名検証は実行しません」 | 文の区切りを句点に。並列は中黒 |
| T-15 | 未判定の内訳 | 「シンボリックリンク先 不明（0 バイトのデコイ）」 | 「シンボリックリンク先不明（0 バイトのデコイ）」 | 不要な空白を削除 |

変えないもの: 重大度の値（CRITICAL など。CLI と findings.json と共通）、「0 件 ＝ 安全と表示しません」系の注意書き、「L3 は『署名済みファイル』であることのみを示し…」、タブ名、「すべてのタブ」（E2E の名前）、「オフライン・外部通信ゼロ」。

---

## 11. 状態とデータの流れ（変更なし）

- `ScanProvider`（Context＋`useReducer`）、`Action` の型、`engine/*` の純関数、`findingsForTab`、`TABS`（§7.2 の順）は**変えない**。
- 増える状態は UI のローカル状態だけ。
  - テーマ: `useTheme()`。localStorage の `zes-theme` を try/catch で読み書きする。
  - タブ検索の文字列: Command の内部状態（Context には入れない）。
  - Popover、Sheet、DropdownMenu の開閉: 各コンポーネントのローカル状態。
- タブの選択は今と同じく `dispatch({type:'SET_TAB'})`。Radix Tabs は **controlled**（`value={state.ui.activeTab}`、`onValueChange`）で使い、状態の持ち主は reducer のままにする。


---

## 12. ディレクトリ構成（予定）

```text
ui/
├── components.json                 ← shadcn CLI の設定（style: new-york、tailwind.config: ""、cssVariables: true、aliases は @/…）
├── vite.config.ts                  ← resolve.alias: '@' と 'react-remove-scroll' → src/lib/remove-scroll-csp.tsx を追加
├── tsconfig.json                   ← paths: { "@/*": ["./src/*"] }
├── scripts/inline-build.mjs        ← 変更なし（CSP は同じ形）。<style> の数が 1 のままであることを検査に足す
└── src/
    ├── lib/
    │   ├── utils.ts                ← cn() = twMerge(clsx(...))
    │   └── remove-scroll-csp.tsx   ← react-remove-scroll の互換（CSSOM でロック。§4.2）
    ├── components/
    │   ├── ui/                     ← shadcn から取り込んで手を入れたもの（コミット対象）
    │   │   ├── alert.tsx  badge.tsx  button.tsx  card.tsx  command.tsx  dropdown-menu.tsx
    │   │   ├── input.tsx  native-select.tsx  popover.tsx  separator.tsx  sheet.tsx
    │   │   ├── table.tsx  tabs.tsx  textarea.tsx  toggle-group.tsx  tooltip.tsx  toast.tsx（自作の移植）
    │   ├── brand/  Logo.tsx  Mark.tsx           ← brand/logo の SVG を JSX にしたもの
    │   ├── severity/  SeverityMark.tsx  SeverityTag.tsx  Stamp.tsx  Tag.tsx  severity.ts（トークンとアイコンの対応表）
    │   ├── layout/  Header.tsx  TabBar.tsx  TabSearch.tsx  ThemeToggle.tsx
    │   ├── overview/  Intake.tsx（空の状態のドロップ先）  SpecimenForm.tsx（検体票）  Tally.tsx（集計＝フィルタ）  FindingsTable.tsx  FindingList.tsx（<640）  FindingSheet.tsx（詳細シート）
    │   │             PasteCheck.tsx  BlastRadius.tsx  CliOnlyNotice.tsx  Undetermined.tsx（欄外の <section>）
    │   ├── skillpact/  SkillPactTab.tsx  SkillList.tsx  SkillPactViewer.tsx  EffectMatrix.tsx  LevelBadge.tsx  …
    │   └── viewers/  McpViewer.tsx  ActionsViewer.tsx  ExtensionViewer.tsx
    ├── hooks/  useTheme.ts  useMediaQuery.ts
    ├── styles/index.css            ← §5.4
    ├── engine/  state/  tabs/      ← 変更なし
```
- shadcn CLI（`npx shadcn add`）は**ネットワークを使う開発時の道具**。成果物の実行時には関係ないが、供給網の観点から CLI は使わず、レジストリの JSON（`https://ui.shadcn.com/r/styles/new-york-v4/<name>.json`）を確かめたうえでソースを手で取り込み、取り込んだ版をコミットのメッセージに書く運用を推奨する（承認済み §16-6）。


---

## 13. 移行計画（小さな段階に分ける。各段階でビルド・Vitest・E2E を通してから次へ）

| # | 内容 | 確かめること |
|---|---|---|
| 0 | React 18.3.1 → 19.x（§16-2 で決定）、@types/react を更新。UI のコードは変えない | 全 E2E、`verify-no-network`、20,000 ファイルの性能 |
| 1 | 土台: `@/` エイリアス、`components.json`（参照用。CLI は使わない）、`lib/utils.ts`（clsx＋tailwind-merge）、tokens の CSS（現行の色に近い値から）、tw-animate-css。**見た目は変えない** | ビルドのサイズ、CSP、E2E |
| 2 | `remove-scroll-csp` の互換モジュールと、CSP 違反を検出する E2E（`securitypolicyviolation` を数える）を先に入れる。Firefox と WebKit でも実行する | 3 エンジンとも違反 0 |
| 3 | 末端の部品: Button（ink / outline / ghost / icon）、SeverityMark、SeverityTag、Tag、Stamp、Card（台紙）、Alert、Input、Textarea、Native Select、lucide のアイコン、ブランドのロゴ | E2E、axe（コントラスト）、目視でモックアップと比べる |
| 4 | 「検疫台」のトークン（§5）に切り替え、ダークの見た目をモックアップに合わせる。検体票、集計（サマリカードとチップの統合）、欄外の `<section>` 化もここで行う | コントラストの自動検査（axe の color-contrast を 0 件） |
| 5 | Tabs（manual）、Tooltip、ToggleGroup（集計） | キーボード操作の E2E |
| 6 | 「すべてのタブ」を Popover＋Command（デスクトップ）と Sheet＋Command（モバイル）に替え、E2E を書き換える（§14） | 検索、IME、Escape でフォーカスが戻ること |
| 7 | モバイルのレイアウト（ヘッダーの DropdownMenu、検出のカード型リスト、詳細シート、貼り付けのシート） | 320 / 375 / 768 の横はみ出しの E2E |
| 8 | ライトテーマとテーマ切替（§16-1 で決定） | 両テーマで axe |
| 9 | 片付け: 自作の Icon / Button / Pill、直書きの色を削除し、`grep '#[0-9a-f]\{6\}' src/components` が 0 件になるようにする | サイズの最終値を記録 |

- 各段階は 1 PR。リリースの判断は段階 4（ダークの見た目が揃った時点）と段階 8 のあと。
- 戻すのが楽なように、段階 1〜3 は旧トークンの名前（`--color-surface` など）を残した別名にしておく。

---

---

## 14. テストへの影響

**維持するもの**（DOM の属性を変えない）: `data-testid` は dir-input、dropzone、paste、paste-submit、import-input、import-status、export、bundle、scan-status（検体票の「スキャン完了」の欄）、count-*（集計の数字）、filter-*（集計の区画）、card-SAFE（SAFE の文）、search、findings-table、finding-row、blast-radius、cli-only、undetermined、skillpact-viewer、skill-item、l3-badge、l3-note、prose-alert、diff-alert、rule-row、mcp-viewer、actions-viewer、extension-viewer、render-error、render-error-reset、all-tabs。`data-level`、`data-severity`、`data-effect`、`data-divergence`、`data-status`、`data-risk`、`data-kind` も維持する。`role=tab` が 18 個、`aria-selected`、`role=tabpanel`、`role=status`（トースト）も同じ。

**変わるもの**:
| テスト | 理由 | 書き換え |
|---|---|---|
| 「すべてのタブ」メニュー（`getByRole('menu', {name:'すべてのタブ'})`、`menuitem` が最初にフォーカスされる、↓ と Enter で SkillPact が選ばれる） | Command に替わるので、`combobox`（入力欄に自動でフォーカス）と `listbox` / `option` になる。cmdk は最初の項目を選択済みにして `aria-activedescendant` で示す | `getByRole('dialog', {name:'すべてのタブ'})` → 入力欄にフォーカスがあること → ↓ と Enter で SkillPact。Escape と外側クリックで閉じ、`all-tabs` にフォーカスが戻ることはそのまま検査する |
| 見出し `getByRole('heading', {name:'Zero-Exec Shield'})` | 表記が小文字になる | 書き換え不要（`name` は既定で大文字小文字を区別しない部分一致。`exact` の指定なし） |
| `getByRole('tabpanel').locator(...)` で Portal の中の要素を探す箇所 | Tooltip や Popover は tabpanel の外に描画される | 現行のテストでは該当なし。新しく書くテストは `page` 全体で探す |
| `card-CRITICAL` / `card-HIGH` / `card-MEDIUM` | サマリカードを集計に統合したため廃止 | 現行の `tests/e2e/app.spec.ts` は参照していない（`grep` で確認）。`count-*` と `filter-*` は同じ名前で集計に残る。`filter-CRITICAL` を押すと一覧が絞られる既存の検査はそのまま通る |
| 横はみ出しのテスト（幅ごと） | モバイルのレイアウトが変わる | 期待値（`scrollWidth ≤ clientWidth`）はそのまま。対象の幅に 320 を足す |
| 追加: CSP 違反ゼロ | §4.2 | `securitypolicyviolation` を数え、全タブ、メニュー、Sheet、Tooltip、トーストを開いたあとに 0 件であること |
| 追加: SkillPact に緑が無い | C-10 | 既存の `[data-severity=SAFE], .text-safe, .bg-safe` が 0 件の検査に `.border-safe` を足す。`[data-testid=l3-badge]` の計算後の色が `--signed` であること |
| 追加: フォーカスが見える | C-05 | Tab で各部品に移ったとき `outline-style` が `solid`、`outline-width` が 2px であること（両テーマ） |
| 追加: 320px の集計 | §8.2 | 320px で集計が 2 列になり、チェックと語が重ならないこと（`getBoundingClientRect` の交差なし） |
| 追加: テーマ | §5.4 | `colorScheme: 'light'` で `html` の `color-scheme` が light になること、テーマ切替の結果が保存されること（localStorage が使えないときも例外にならないこと） |

---

---

## 15. リスク

| # | リスク | 影響 | 対策 |
|---|---|---|---|
| R-1 | Radix の更新で `<style>` の差し込みが増える | CSP 違反、E2E 失敗 | バージョンを固定し、CSP 違反ゼロの E2E を CI に置く。`inline-build.mjs` で、バンドル内の `createElement("style")` と `dangerouslySetInnerHTML` を grep し、許可リスト外なら失敗させる |
| R-2 | `react-remove-scroll` の互換モジュールが Radix の内部 API の変更で壊れる（Radix が渡す props: `as`、`allowPinchZoom`、`shards`、`enabled`） | スクロールロックや描画が壊れる | 互換モジュールの単体テスト（Dialog を開いて閉じる）。Radix を更新するときの確認項目に入れる |
| R-3 | バンドルが +38〜56% 増える | `file://` での解析時間 | §4.3 の削り方。20,000 ファイルの性能 E2E で確かめる |
| R-4 | 依存が約 30 増える（供給網） | このツールの性質上、信頼に関わる | 固定、`--ignore-scripts`、取り込むソースの手動レビュー、`@radix-ui/*` の個別パッケージだけを入れる |
| R-5 | React 18 で shadcn v4 の部品を使うと ref が渡らない（実測） | メニューの位置ずれ、コンソールのエラー | §4.2 の案 A か案 B |
| R-6 | Firefox / WebKit の `file://` での CSP の挙動（未検証） | 環境によって表示が崩れる | 段階 2 で 3 エンジンの E2E |
| R-7 | テーマ切替で localStorage が使えない（`file://` で無効にされている場合） | 例外 | try/catch。保存できなくても表示は OS の設定に従う |
| R-8 | cmdk の絞り込みが日本語の部分一致でぶれる（cmdk の既定はあいまい検索のスコア） | 検索結果が直感と違う | `shouldFilter={false}` にし、正規化（NFKC と小文字化）した部分一致の自作フィルタを使う（`keywords` は表示名＋別名＋§番号） |
| R-9 | shadcn のドキュメントやレジストリの変化が速い（Base UI 版の追加、Toast と Sonner の食い違い） | 取り込む時期によって中身が違う | 取り込んだソースは自分のコードとして扱う。レジストリの JSON のハッシュを記録する |
| R-10 | （v0.1 の「ティールのフォーカスが SAFE に見える」） | — | **解消**。フォーカスは墨、ティールは UI に使わない |
| R-11 | 罫を多用すると新聞風（A-15）に寄る | 既定の見た目に戻る | 罫は記録の区切りにだけ使う。角丸を残す。段組は 2 列まで。レビューの観点に入れる |
| R-12 | 色を検出に限ったので、主ボタン（墨）が目立たないと感じる人がいる | 操作の迷い | 主ボタンは 1 画面に 1 つ（「フォルダを選択…」）だけにし、墨の塗りで最大のコントラスト（13.4:1）を持たせる。ユーザビリティの確認で見る |
| R-13 | 「実行 0 回」が常に 0 で、情報として冗長に見える | 文言の信頼性 | 製品の約束として残し、Tooltip で根拠（ZES はファイルを実行・インストールしない）を示す。不要と判断したら欄ごと消せる構造にする |


---

## 16. 決定事項（オーナー承認済み）

v0.1 の §16 の 9 項目はすべて承認された。3 だけは、承認後に出た条件（「AIっぽいデザインはやめて」）で見直した。

| # | 内容 | 決定 | v0.2 での扱い |
|---|---|---|---|
| 1 | ライトテーマを追加する（既定はダーク、OS の設定にも従う） | **決定** | §5.2、§5.4。両テーマのモックアップを作った |
| 2 | React 19 に上げる（案 A、+79 KiB） | **決定** | 移行の段階 0（§13） |
| 3 | 背景をブランドの紺 `#060a13`、primary をブランドのブルーにする | **見直して変更** | 紺＋ブルーは A-1 そのもので、ブルーとティールは LOW と SAFE に近い。作業台（グラファイト / 紙）と墨にし、ブランドの色はアイコンの中だけに残す（§5.1 R-1〜R-3） |
| 4 | 「すべてのタブ」をタブ検索（cmdk の Command）に変える | **決定** | §10.2 |
| 5 | モバイルで検出の行を押すと詳細のシートを開く | **決定** | §10.4 |
| 6 | shadcn CLI を使わず、ソースを手で取り込む | **決定** | 取り込むときに見た目のクラスを「検疫台」に書き換える（§9） |
| 7 | Sonner を採らず、自作のトーストを残す | **決定** | §9 |
| 8 | tailwind-merge を残す | **決定** | §13 の段階 1 |
| 9 | ヘッダーの「外部通信ゼロ」を中立色にする | **決定** | 無彩色の `Tag`（§10.1）。文言は現行の「オフライン・外部通信ゼロ」のまま |

### 16.1 残っている確認事項
- なし（設計で決められることは決めた）。実装の段階 4 のあと、実機（macOS のヒラギノ、Windows の Yu Gothic UI）で検体票の等幅 26px と和文の並びを目視で確かめる。

---

## 付録 A. 検証の記録
- パレット: `scripts/palette.py` → `palette.json`。両テーマで次を計算し、基準を下回れば終了コード 1。
  - 墨と鉛筆: 作業台、台紙、浮き、凹み、選択行の上で 4.5 以上。
  - 縁: 作業台、台紙、凹みの上で 3.0 以上。
  - 7 種の文字色: 淡色地、作業台、台紙、浮き、選択行の上で 4.5 以上。
  - CRITICAL の塗りの白字: 4.5 以上。
  - 結果: **すべて合格**。最小値は、文字がライトの HIGH / 作業台の 4.98、部品の枠がライトの縁 / 作業台の 3.37。
- モックアップ: `scripts/mockups.py`（総合とモバイル）、`skillpact.py`、`tokens.py`、`lib.py`（Pillow で実際のフォントの文字幅を測ってレイアウト）→ `*.svg`。`scripts/render.mjs`（Playwright の Chromium）→ `mock-png/`。`scripts/sheet.py` → `sheet.png`。描画して目視し、次を直した。
  - 検体票の注記とボタンの重なり。
  - Tooltip がモジュールの列と上の行に重なる。
  - SVG が先頭の空白を詰めて「62/ 67」になる。
  - 集計の淡色地の塗りが重い（帯とチェックだけにした）。
  - 集計のフォーカスの見本が選択と紛らわしい（コピーボタンに移した）。
  - タブの件数のアイコンが「©」に見える（淡色地の数字にした）。
  - ダークの作業台が黒に近い（L 0.235 → 0.255）。
  - 欄外の見出しのアイコン（削除）。
- v0.1 から引き継いだ実測（変更なし）:
  - 撮影: `scripts/shots.mjs` → `current/`。
  - CSP: `scripts/csp-test.mjs`、`scripts/attr.mjs`。
  - React 18 の ref: `scripts/ref18.mjs`。
  - 実験用のビルド: `../design-shadcn/lab/`、`../design-shadcn/lab19/`。
  - バンドル: esbuild 0.25.10。
  - 使ったバージョン: v0.1 の付録 A のとおり。
