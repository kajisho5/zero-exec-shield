// §10 / §26 / §27 / §28 / §30 / §31 / §32 / §33 / §35 / §36 / §40 / §43 / §48
// ブラウザで判定できるのは「投入されたファイルの中身」まで。ホスト状態は CliOnlyNotice で CLI に案内する。
import { HOME_RC_FILES, homeLike, named, push, readable, rootRel, type RuleCtx } from '../context';
import { extname } from '../util';

const RC = /(^|\/)(\.bashrc|\.bash_profile|\.profile|\.zshrc|\.zprofile|\.zshenv|\.zlogin|\.bash_login)$/;

export function buildHookRules(ctx: RuleCtx): void {
  ctx.checks.add('s27-buildrs').add('s27-gogenerate').add('s27-backend').add('s27-cmdclass');
  const safe = ctx.ioc.build_hooks.py_build_backend_safe;
  for (const f of readable(ctx)) {
    if (f.name === 'build.rs') {
      const cmd = /(Command::new|process::Command)/.test(f.text);
      if (cmd && /"(curl|wget|sh|bash|powershell|cmd)"|(curl|wget)/.test(f.text)) push(ctx, { level: 'HIGH', module: '§27', campaign: null, path: f.relPath, detail: 'build.rs がビルド時に外部コマンド（curl/wget/シェル）を起動', ruleId: 's27-buildrs', evidenceSha: f.sha256 });
      else if (cmd) push(ctx, { level: 'MEDIUM', module: '§27', campaign: null, path: f.relPath, detail: 'build.rs がビルド時にプロセスを起動', ruleId: 's27-buildrs', evidenceSha: f.sha256 });
      else if (/(include_bytes!|include_str!)/.test(f.text)) push(ctx, { level: 'LOW', module: '§27', campaign: null, path: f.relPath, detail: 'build.rs がバイナリ/文字列を埋め込み', ruleId: 's27-buildrs', evidenceSha: f.sha256 });
    } else if (f.name.endsWith('.go') && /^\/\/go:generate\s+(curl|wget|bash|sh\s+-c)/m.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§27', campaign: null, path: f.relPath, detail: '//go:generate で外部コマンド（curl/bash/sh -c）', ruleId: 's27-gogenerate', evidenceSha: f.sha256 });
    } else if (f.name === 'pyproject.toml') {
      const be = /^\s*build-backend\s*=\s*["']([^"']+)["']/m.exec(f.text)?.[1];
      if (be && !safe.includes(be)) push(ctx, { level: 'MEDIUM', module: '§27', campaign: null, path: f.relPath, detail: 'pyproject.toml の build-backend が既知安全リスト外', ruleId: 's27-backend', evidenceSha: f.sha256 });
      if (/^\s*backend-path\s*=/m.test(f.text)) push(ctx, { level: 'HIGH', module: '§27', campaign: null, path: f.relPath, detail: 'pyproject.toml の backend-path でリポジトリ内ビルドバックエンドを使用', ruleId: 's27-backend-path', evidenceSha: f.sha256 });
    } else if (f.name === 'setup.py' && /cmdclass/.test(f.text)) {
      const bad = /(urllib|requests\.|subprocess|os\.system|socket|b64decode|exec\()/.test(f.text);
      push(ctx, { level: bad ? 'HIGH' : 'MEDIUM', module: '§27', campaign: null, path: f.relPath, detail: bad ? 'setup.py の cmdclass に通信/実行処理（インストール時実行）' : 'setup.py が cmdclass を上書き（インストール時に任意コード）', ruleId: 's27-cmdclass', evidenceSha: f.sha256 });
    }
  }
}

export function modelSupplyRules(ctx: RuleCtx): void {
  ctx.checks.add('s32-pickle-ext').add('s32-weights-only').add('s32-extra-index').add('s36-trust-remote').add('s36-dataset-exec').add('s36-pickle-load');
  for (const f of ctx.files) {
    const e = extname(f.name);
    if (f.relPath.includes('node_modules/')) continue;
    if (['pkl', 'pickle', 'pt'].includes(e) || (e === 'bin' && /\/(models?|checkpoints?|weights)\/|pytorch_model[^/]*\.bin$/.test('/' + f.relPath))) {
      push(ctx, { level: 'MEDIUM', module: '§32', campaign: 'hf-supply-chain', path: f.relPath, detail: `pickle 系モデル形式（.${e}）。読み込み時に任意コード実行の可能性（.safetensors 推奨）`, ruleId: 's32-pickle-ext', evidenceSha: f.sha256 });
    }
  }
  for (const f of readable(ctx)) {
    if (/\.(py|ipynb)$/.test(f.name) && /weights_only\s*=\s*False/.test(f.text)) push(ctx, { level: 'HIGH', module: '§32', campaign: 'hf-supply-chain', path: f.relPath, detail: 'torch.load(..., weights_only=False)（pickle の任意コード実行）', ruleId: 's32-weights-only', evidenceSha: f.sha256 });
    if (/^(requirements.*\.txt|constraints.*\.txt|pip\.conf)$/.test(f.name) && /extra-index-url/.test(f.text)) push(ctx, { level: 'HIGH', module: '§32', campaign: 'hf-supply-chain', path: f.relPath, detail: '--extra-index-url（PyPI 以外の索引との依存関係混乱）', ruleId: 's32-extra-index', evidenceSha: f.sha256 });
    if (/\.(py|ipynb|json|ya?ml)$/.test(f.name) && /trust_remote_code["']?\s*[=:]\s*(True|true)/.test(f.text)) push(ctx, { level: 'HIGH', module: '§36', campaign: 'hf-supply-chain', path: f.relPath, detail: 'trust_remote_code=True（リモートのモデル/データセットコードを実行）', ruleId: 's36-trust-remote', evidenceSha: f.sha256 });
    if (f.name.endsWith('.py') && /(GeneratorBasedBuilder|DatasetBuilder|datasets\.load_dataset|_split_generators)/.test(f.text) && /(subprocess|os\.system|eval\(|exec\(|__import__)/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§36', campaign: 'hf-dataset-poisoning', path: f.relPath, detail: 'データセットローダースクリプトに subprocess/eval/exec（コード実行経路）', ruleId: 's36-dataset-exec', evidenceSha: f.sha256 });
    }
    if (f.name.endsWith('.py') && !/(site|dist)-packages\/|node_modules\//.test(f.relPath) && /(def __reduce__|pickle\.loads?\(|dill\.loads?\(|cloudpickle\.loads?\()/.test(f.text)) {
      push(ctx, { level: 'MEDIUM', module: '§36', campaign: 'hf-supply-chain', path: f.relPath, detail: 'pickle 系デシリアライズ（__reduce__/pickle.loads/dill）', ruleId: 's36-pickle-load', evidenceSha: f.sha256 });
    }
  }
}

export function persistenceRules(ctx: RuleCtx): void {
  ctx.checks.add('s10-rc').add('s26-gitconfig').add('s26-envrc').add('s30-launchagent').add('s31-ldpreload').add('s31-autostart').add('s33-prompt').add('s35-history');
  for (const f of readable(ctx)) {
    const p = f.relPath;
    if (RC.test(p)) {
      if (/(curl|wget)[^|#\n]*\|\s*(ba|z)?sh/.test(f.text)) push(ctx, { level: 'HIGH', module: '§10', campaign: null, path: p, detail: 'シェル設定に curl|sh 形式のリモート実行', ruleId: 's10-rc:curlsh', evidenceSha: f.sha256 });
      if (/base64\s+(-d|--decode)/.test(f.text)) push(ctx, { level: 'HIGH', module: '§10', campaign: null, path: p, detail: 'シェル設定に難読化コード（base64 -d）', ruleId: 's10-rc:base64', evidenceSha: f.sha256 });
      if (/(^|\s|export\s+)LD_PRELOAD=/m.test(f.text)) push(ctx, { level: 'HIGH', module: '§31', campaign: 'ebpf-rootkit', path: p, detail: 'シェル設定で LD_PRELOAD を設定（ライブラリ注入による永続化）', ruleId: 's31-ldpreload:rc', evidenceSha: f.sha256 });
      if (/DYLD_INSERT_LIBRARIES/.test(f.text)) push(ctx, { level: 'HIGH', module: '§30', campaign: null, path: p, detail: 'DYLD_INSERT_LIBRARIES の設定（ライブラリインジェクション）', ruleId: 's30-dyld', evidenceSha: f.sha256 });
      if (/(^|\s)PROMPT_COMMAND=/m.test(f.text)) push(ctx, { level: /PROMPT_COMMAND=.*(curl|wget|base64|nc |\/dev\/tcp)/.test(f.text) ? 'HIGH' : 'MEDIUM', module: '§33', campaign: null, path: p, detail: 'PROMPT_COMMAND が設定されています（プロンプト表示ごとに実行）', ruleId: 's33-prompt', evidenceSha: f.sha256 });
      if (/(HISTFILE=\/dev\/null|HISTSIZE=0([^0-9]|$)|HISTFILESIZE=0([^0-9]|$)|SAVEHIST=0([^0-9]|$)|unset\s+HISTFILE)/m.test(f.text)) push(ctx, { level: 'HIGH', module: '§35', campaign: null, path: p, detail: 'シェル履歴の無効化（HISTFILE=/dev/null / HISTSIZE=0）', ruleId: 's35-history', evidenceSha: f.sha256 });
    }
    if (f.name === 'ld.so.preload' && f.text.split(/\r?\n/).some((l) => l.trim() && !l.trim().startsWith('#'))) {
      push(ctx, { level: 'CRITICAL', module: '§31', campaign: 'ebpf-rootkit', path: p, detail: 'ld.so.preload が空ではありません（全プロセスへのライブラリ注入）', ruleId: 's31-ldpreload:file', evidenceSha: f.sha256 });
    }
    if (/(^|\/)(\.gitconfig|\.git\/config)$/.test(p) || /(^|\/)\.config\/git\/config$/.test(p)) {
      if (/^\s*fsmonitor\s*=/im.test(f.text) && !/^\s*fsmonitor\s*=\s*(true|false)\s*$/im.test(f.text)) push(ctx, { level: 'CRITICAL', module: '§26', campaign: null, path: p, detail: 'core.fsmonitor に外部コマンド（git 操作のたびに実行）', ruleId: 's26-gitconfig:fsmonitor', evidenceSha: f.sha256 });
      if (/^\s*sshCommand\s*=/im.test(f.text)) push(ctx, { level: 'HIGH', module: '§26', campaign: null, path: p, detail: 'core.sshCommand が設定されています', ruleId: 's26-gitconfig:ssh', evidenceSha: f.sha256 });
      if (/^\s*hooksPath\s*=/im.test(f.text)) push(ctx, { level: 'MEDIUM', module: '§26', campaign: null, path: p, detail: 'core.hooksPath が設定されています（フック置き場の付け替え）', ruleId: 's26-gitconfig:hooks', evidenceSha: f.sha256 });
    }
    if (f.name === '.envrc' && /(curl|wget)[^|#\n]*\|\s*(ba|z)?sh|eval\s+"?\$\((curl|wget)/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§26', campaign: null, path: p, detail: '.envrc がリモートスクリプトを実行（direnv: curl|bash）', ruleId: 's26-envrc', evidenceSha: f.sha256 });
    }
    if (/(^|\/)LaunchAgents\/[^/]+\.plist$|(^|\/)LaunchDaemons\/[^/]+\.plist$/.test(p)) {
      const label = /<key>Label<\/key>\s*<string>([^<]*)<\/string>/.exec(f.text)?.[1];
      if (label && !label.includes('.')) push(ctx, { level: 'HIGH', module: '§30', campaign: null, path: p, detail: 'LaunchAgent/Daemon の Label がランダム文字列様', ruleId: 's30-launchagent:label', evidenceSha: f.sha256 });
      if (/<string>(\/tmp\/|\/private\/tmp\/|\/Users\/Shared\/|\/var\/tmp\/)|<string>[^<]*\/\.[^/<]+\/[^<]*<\/string>/.test(f.text)) push(ctx, { level: 'HIGH', module: '§30', campaign: null, path: p, detail: 'LaunchAgent/Daemon が一時領域/隠しディレクトリのプログラムを起動', ruleId: 's30-launchagent:path', evidenceSha: f.sha256 });
    }
    if (/(^|\/)systemd\/user\/[^/]+\.service$|(^|\/)autostart\/[^/]+\.desktop$/.test(p) && /^\s*(ExecStart|ExecStartPre|Exec)\s*=[^#\n]*(\/tmp\/|\/dev\/shm\/|\/var\/tmp\/|\/\.[^/\s]+\/|curl|wget|base64|bash -c|sh -c)/m.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§31', campaign: 'ebpf-rootkit', path: p, detail: '自動起動エントリが一時領域/隠しパス/通信コマンドを実行', ruleId: 's31-autostart', evidenceSha: f.sha256 });
    }
  }
}

export function ebpfRules(ctx: RuleCtx): void {
  ctx.checks.add('s40-loader').add('s40-names');
  for (const f of readable(ctx)) {
    if (!/\.(sh|bash|py|c|go|rs|service|conf)$/.test(f.name) && f.name.includes('.')) continue;
    if (/(>>?\s*\/etc\/ld\.so\.preload|bpftool\s+prog\s+(load|attach)|bpf_probe_write_user|BPF_PROG_LOAD|insmod\s|modprobe\s+-f)/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§40', campaign: 'ebpf-rootkit', path: f.relPath, detail: 'ld.so.preload 書き込み / eBPF プログラムのロード / カーネルモジュール挿入', ruleId: 's40-loader', evidenceSha: f.sha256 });
    }
    if (/(quasar[ _-]?linux|\bQLNX\b|linkpro|voidlink)/i.test(f.text)) {
      push(ctx, { level: 'CRITICAL', module: '§40', campaign: 'ebpf-rootkit', path: f.relPath, detail: 'Quasar Linux (QLNX) / LinkPro / VoidLink の痕跡', ruleId: 's40-names', evidenceSha: f.sha256 });
    }
  }
}

export function sigstoreRules(ctx: RuleCtx): void {
  ctx.checks.add('s28-cosign-key').add('s43-identity').add('s43-slsa').add('s48-provenance');
  for (const f of named(ctx, /^cosign\.key$/)) push(ctx, { level: 'HIGH', module: '§28', campaign: null, path: f.relPath, detail: 'cosign 秘密鍵（cosign.key）が検査対象内にあります', ruleId: 's28-cosign-key', evidenceSha: f.sha256 });
  for (const f of readable(ctx).filter((x) => /\.(sh|bash|ya?ml|mk)$|(^|\/)(Makefile|Jenkinsfile)$/.test(x.relPath))) {
    const joined = f.text.replace(/\\\r?\n/g, ' ');
    for (const line of joined.split(/\r?\n/)) {
      if (!/cosign\s+verify(-blob|-attestation|-blob-attestation)?(\s|$)/.test(line) || /--key([\s=]|$)/.test(line)) continue;
      if (!/--certificate-identity(-regexp)?[\s=]/.test(line)) {
        push(ctx, { level: 'HIGH', module: '§43', campaign: null, path: f.relPath, detail: 'cosign verify に --certificate-identity がありません（任意の署名者を受理）', ruleId: 's43-identity', evidenceSha: f.sha256 });
      } else if (!/--certificate-oidc-issuer(-regexp)?[\s=]/.test(line)) {
        push(ctx, { level: 'HIGH', module: '§43', campaign: null, path: f.relPath, detail: 'cosign verify に --certificate-oidc-issuer がありません', ruleId: 's43-issuer', evidenceSha: f.sha256 });
      }
    }
    if (/slsa-verifier\s+verify-/.test(f.text) && !/--source-uri/.test(f.text)) push(ctx, { level: 'HIGH', module: '§43', campaign: null, path: f.relPath, detail: 'slsa-verifier に --source-uri がありません', ruleId: 's43-slsa', evidenceSha: f.sha256 });
  }
  const sboms = named(ctx, /(\.spdx\.json|\.cdx\.json|^bom\.json$|^sbom\.json$|\.spdx$|^cyclonedx\.json$)/);
  const prov = named(ctx, /(\.intoto\.jsonl|^provenance\.json$|\.provenance\.json$|\.layout$)/).length > 0;
  const verify = readable(ctx).some((x) => /(cosign\s+verify-attestation|slsa-verifier\s+verify-artifact|in-toto-verify)/.test(x.text));
  if (sboms.length && !prov && !verify) {
    push(ctx, { level: 'MEDIUM', module: '§48', campaign: null, path: sboms[0]?.relPath ?? null, detail: 'SBOM はあるが provenance / in-toto レイアウト / attestation 検証が見当たりません', ruleId: 's48-provenance' });
  }
}

export function credentialRules(ctx: RuleCtx): void {
  ctx.checks.add('s47-github-token').add('s47-history-export');
  for (const f of readable(ctx)) {
    if (/(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})/.test(f.text)) {
      push(ctx, { level: 'CRITICAL', module: '§47', campaign: null, path: f.relPath, detail: 'GitHub トークンがファイルに含まれます（内容は表示しません。即時失効）', ruleId: 's47-github-token', evidenceSha: f.sha256 });
    }
    if (/(^|\/)\.(bash|zsh)_history$/.test(f.relPath) && /export\s+[A-Za-z0-9_]*(_TOKEN|_KEY|_SECRET|PASSWORD)=/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§47', campaign: null, path: f.relPath, detail: 'シェル履歴に export *_TOKEN= 等（平文の認証情報）', ruleId: 's47-history-export', evidenceSha: f.sha256 });
    }
  }
}

/**
 * 投入フォルダを HOME と見なせるとき（homeLike）だけ行う、CLI の HOME 前提の検査。
 *   §10: ~/Library/LaunchAgents/*.plist（参考 INFO）・対話履歴ファイルの存在
 *   §12: ワクチン 3 点（~/.npmrc の ignore-scripts=true、シェル設定の PYTHONNOUSERSITE=1 / PIP_REQUIRE_VIRTUALENV、pip.conf）
 * 環境変数（npm_config_ignore_scripts 等）はブラウザから読めないため、CLI のホスト検査を無効にしたときと同じくファイルだけで判定する。
 */
export function homeRules(ctx: RuleCtx): void {
  if (!homeLike(ctx)) return;
  ctx.checks.add('s10-home').add('s12-vaccines');
  const at = (rel: string) => ctx.files.find((f) => rootRel(ctx, f) === rel);
  const prefix = ctx.root ? `${ctx.root}/` : '';
  for (const f of ctx.files) {
    const rel = rootRel(ctx, f);
    if (/^Library\/LaunchAgents\/[^/]+\.plist$/.test(rel)) push(ctx, { level: 'INFO', module: '§10', campaign: null, path: f.relPath, detail: 'LaunchAgent（§30 で詳細検査）', ruleId: 's10-home:launchagent', evidenceSha: f.sha256 });
    if (/^\.(lesshst|viminfo|python_history|node_repl_history|mysql_history|psql_history)$/.test(rel)) push(ctx, { level: 'INFO', module: '§10', campaign: null, path: f.relPath, detail: '対話履歴ファイル（内容は読み取りません。侵害時はシークレット混入を確認）', ruleId: 's10-home:history' });
  }
  const text = (rel: string) => at(rel)?.text ?? '';
  const rc = HOME_RC_FILES.map(text).join('\n');
  if (!/^\s*ignore-scripts\s*=\s*true/m.test(text('.npmrc'))) push(ctx, { level: 'MEDIUM', module: '§12', campaign: null, path: `${prefix}.npmrc`, detail: 'npm の ignore-scripts=true が未設定', ruleId: 's12-vaccines:npm' });
  if (!/PYTHONNOUSERSITE=1/.test(rc)) push(ctx, { level: 'MEDIUM', module: '§12', campaign: null, path: null, detail: 'PYTHONNOUSERSITE=1 が未設定（ユーザー site-packages 経由のフック実行）', ruleId: 's12-vaccines:pythonnousersite' });
  const pipConf = ['.config/pip/pip.conf', '.pip/pip.conf', 'Library/Application Support/pip/pip.conf'].some((p) => /^\s*require-virtualenv\s*=\s*(true|1)/m.test(text(p)));
  if (!/PIP_REQUIRE_VIRTUALENV=(true|1)/.test(rc) && !pipConf) push(ctx, { level: 'MEDIUM', module: '§12', campaign: null, path: null, detail: 'PIP_REQUIRE_VIRTUALENV=true が未設定（グローバル環境への pip install）', ruleId: 's12-vaccines:pip' });
}
