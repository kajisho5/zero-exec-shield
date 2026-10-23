// §10 / §26 / §27 / §28 / §30 / §31 / §32 / §33 / §35 / §36 / §40 / §43 / §48
// ブラウザで判定できるのは「投入されたファイルの中身」まで。ホスト状態は CliOnlyNotice で CLI に案内する。
import { HOME_RC_FILES, homeLike, named, push, readable, rootRel, type RuleCtx } from '../context';
import { extname, textLocators } from '../util';
import { collectDeps } from './supplyChain';

const RC = /(^|\/)(\.bashrc|\.bash_profile|\.profile|\.zshrc|\.zprofile|\.zshenv|\.zlogin|\.bash_login)$/;

export function buildHookRules(ctx: RuleCtx): void {
  ctx.checks.add('s27-buildrs').add('s27-gogenerate').add('s27-backend').add('s27-cmdclass');
  const safe = ctx.ioc.build_hooks.py_build_backend_safe;
  for (const f of readable(ctx)) {
    if (f.name === 'build.rs') {
      const cmd = /(Command::new|process::Command)/.test(f.text);
      if (cmd && /"(curl|wget|sh|bash|powershell|cmd)"|(curl|wget)/.test(f.text)) push(ctx, { level: 'HIGH', module: '§27', campaign: null, path: f.relPath, code: 's27.build_rs_exec', ruleId: 's27-buildrs', evidenceSha: f.sha256 });
      else if (cmd) push(ctx, { level: 'MEDIUM', module: '§27', campaign: null, path: f.relPath, code: 's27.build_rs_process', ruleId: 's27-buildrs', evidenceSha: f.sha256 });
      else if (/(include_bytes!|include_str!)/.test(f.text)) push(ctx, { level: 'LOW', module: '§27', campaign: null, path: f.relPath, code: 's27.build_rs_include', ruleId: 's27-buildrs', evidenceSha: f.sha256 });
    } else if (f.name.endsWith('.go') && /^\/\/go:generate\s+(curl|wget|bash|sh\s+-c)/m.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§27', campaign: null, path: f.relPath, code: 's27.go_generate', ruleId: 's27-gogenerate', evidenceSha: f.sha256 });
    } else if (f.name === 'pyproject.toml') {
      const be = /^\s*build-backend\s*=\s*["']([^"']+)["']/m.exec(f.text)?.[1];
      if (be && !safe.includes(be)) push(ctx, { level: 'MEDIUM', module: '§27', campaign: null, path: f.relPath, code: 's27.build_backend', params: { backend: be }, ruleId: 's27-backend', evidenceSha: f.sha256 });
      if (/^\s*backend-path\s*=/m.test(f.text)) push(ctx, { level: 'HIGH', module: '§27', campaign: null, path: f.relPath, code: 's27.backend_path', ruleId: 's27-backend-path', evidenceSha: f.sha256 });
    } else if (f.name === 'setup.py' && /cmdclass/.test(f.text)) {
      const bad = /(urllib|requests\.|subprocess|os\.system|socket|b64decode|exec\()/.test(f.text);
      push(ctx, { level: bad ? 'HIGH' : 'MEDIUM', module: '§27', campaign: null, path: f.relPath, code: bad ? 's27.cmdclass_exec' : 's27.cmdclass', ruleId: 's27-cmdclass', evidenceSha: f.sha256 });
    }
  }
}

export function modelSupplyRules(ctx: RuleCtx): void {
  ctx.checks.add('s32-pickle-ext').add('s32-weights-only').add('s32-extra-index').add('s36-trust-remote').add('s36-dataset-exec').add('s36-pickle-load').add('s36-lerobot');
  for (const f of ctx.files) {
    const e = extname(f.name);
    if (f.relPath.includes('node_modules/')) continue;
    if (['pkl', 'pickle', 'pt'].includes(e) || (e === 'bin' && /\/(models?|checkpoints?|weights)\/|pytorch_model[^/]*\.bin$/.test('/' + f.relPath))) {
      push(ctx, { level: 'MEDIUM', module: '§32', campaign: 'hf-supply-chain', path: f.relPath, code: 's32.pickle_model', params: { format: f.name.slice(f.name.lastIndexOf('.') + 1) }, ruleId: 's32-pickle-ext', evidenceSha: f.sha256 });
    }
  }
  for (const f of readable(ctx)) {
    if (/\.(py|ipynb)$/.test(f.name) && /weights_only\s*=\s*False/.test(f.text)) push(ctx, { level: 'HIGH', module: '§32', campaign: 'hf-supply-chain', path: f.relPath, code: 's32.torch_load', ruleId: 's32-weights-only', evidenceSha: f.sha256 });
    if (/^(requirements.*\.txt|constraints.*\.txt|pip\.conf)$/.test(f.name) && /extra-index-url/.test(f.text)) push(ctx, { level: 'HIGH', module: '§32', campaign: 'hf-supply-chain', path: f.relPath, code: 's32.extra_index_url', ruleId: 's32-extra-index', evidenceSha: f.sha256 });
    if (/\.(py|ipynb|json|ya?ml)$/.test(f.name) && /trust_remote_code["']?\s*[=:]\s*(True|true)/.test(f.text)) push(ctx, { level: 'HIGH', module: '§36', campaign: 'hf-supply-chain', path: f.relPath, code: 's36.trust_remote_code', ruleId: 's36-trust-remote', evidenceSha: f.sha256 });
    if (f.name.endsWith('.py') && /(GeneratorBasedBuilder|DatasetBuilder|datasets\.load_dataset|_split_generators)/.test(f.text) && /(subprocess|os\.system|eval\(|exec\(|__import__)/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§36', campaign: 'hf-dataset-poisoning', path: f.relPath, code: 's36.dataset_loader', ruleId: 's36-dataset-exec', evidenceSha: f.sha256 });
    }
    if (f.name.endsWith('.py') && !/(site|dist)-packages\/|node_modules\//.test(f.relPath) && /(def __reduce__|pickle\.loads?\(|dill\.loads?\(|cloudpickle\.loads?\()/.test(f.text)) {
      push(ctx, { level: 'MEDIUM', module: '§36', campaign: 'hf-supply-chain', path: f.relPath, code: 's36.pickle', ruleId: 's36-pickle-load', evidenceSha: f.sha256 });
    }
  }
  // lerobot（CVE-2026-25874。ioc に修正版が未定義のため版に依らず要確認。CLI check_s36 と同じく依存インベントリから）
  for (const d of collectDeps(ctx)) {
    if (d.eco === 'pypi' && d.name === 'lerobot') push(ctx, { level: 'HIGH', module: '§36', campaign: 'hf-lerobot-rce', path: d.path, code: 's36.lerobot', params: { version: d.version }, ruleId: `s36-lerobot:${d.version}`, evidenceSha: d.sha });
  }
}

export function persistenceRules(ctx: RuleCtx): void {
  ctx.checks.add('s10-rc').add('s26-gitconfig').add('s26-envrc').add('s30-launchagent').add('s31-ldpreload').add('s31-autostart').add('s33-prompt').add('s35-history');
  for (const f of readable(ctx)) {
    const p = f.relPath;
    if (RC.test(p)) {
      if (/(curl|wget)[^|#\n]*\|\s*(ba|z)?sh/.test(f.text)) push(ctx, { level: 'HIGH', module: '§10', campaign: null, path: p, code: 's10.curl_sh', ruleId: 's10-rc:curlsh', evidenceSha: f.sha256, locators: textLocators(f.text, /(curl|wget)[^|#]*\|\s*(ba|z)?sh/) });
      if (/base64\s+(-d|--decode)/.test(f.text)) push(ctx, { level: 'HIGH', module: '§10', campaign: null, path: p, code: 's10.obfuscated', ruleId: 's10-rc:base64', evidenceSha: f.sha256, locators: textLocators(f.text, /base64\s+(-d|--decode)|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/) });
      if (/(^|\s|export\s+)LD_PRELOAD=/m.test(f.text)) push(ctx, { level: 'HIGH', module: '§31', campaign: 'ebpf-rootkit', path: p, code: 's31.ld_preload_rc', ruleId: 's31-ldpreload:rc', evidenceSha: f.sha256, locators: textLocators(f.text, /(^|\s|export\s+)LD_PRELOAD=/) });
      if (/DYLD_INSERT_LIBRARIES/.test(f.text)) push(ctx, { level: 'HIGH', module: '§30', campaign: null, path: p, code: 's30.dyld_insert', ruleId: 's30-dyld', evidenceSha: f.sha256 });
      if (/(^|\s)PROMPT_COMMAND=/m.test(f.text)) {
        const bad = /PROMPT_COMMAND=.*(curl|wget|base64|nc |\/dev\/tcp)/.test(f.text);
        push(ctx, { level: bad ? 'HIGH' : 'MEDIUM', module: '§33', campaign: null, path: p, code: bad ? 's33.prompt_command_suspicious' : 's33.prompt_command', ruleId: 's33-prompt', evidenceSha: f.sha256 });
      }
      if (/(HISTFILE=\/dev\/null|HISTSIZE=0([^0-9]|$)|HISTFILESIZE=0([^0-9]|$)|SAVEHIST=0([^0-9]|$)|unset\s+HISTFILE)/m.test(f.text)) push(ctx, { level: 'HIGH', module: '§35', campaign: null, path: p, code: 's35.history_disabled', ruleId: 's35-history', evidenceSha: f.sha256 });
    }
    if (f.name === 'ld.so.preload' && f.text.split(/\r?\n/).some((l) => l.trim() && !l.trim().startsWith('#'))) {
      push(ctx, { level: 'CRITICAL', module: '§31', campaign: 'ebpf-rootkit', path: p, code: 's31.ld_so_preload', ruleId: 's31-ldpreload:file', evidenceSha: f.sha256, locators: textLocators(f.text, /.*/, /^\s*(#|$)/) });
    }
    if (/(^|\/)(\.gitconfig|\.git\/config)$/.test(p) || /(^|\/)\.config\/git\/config$/.test(p)) {
      if (/^\s*fsmonitor\s*=/im.test(f.text) && !/^\s*fsmonitor\s*=\s*(true|false)\s*$/im.test(f.text)) push(ctx, { level: 'CRITICAL', module: '§26', campaign: null, path: p, code: 's26.fsmonitor', ruleId: 's26-gitconfig:fsmonitor', evidenceSha: f.sha256, locators: textLocators(f.text, /^\s*fsmonitor\s*=/i, /^\s*fsmonitor\s*=\s*(true|false)\s*$/i) });
      if (/^\s*sshCommand\s*=/im.test(f.text)) push(ctx, { level: 'HIGH', module: '§26', campaign: null, path: p, code: 's26.ssh_command', ruleId: 's26-gitconfig:ssh', evidenceSha: f.sha256, locators: textLocators(f.text, /^\s*sshCommand\s*=/i) });
      if (/^\s*hooksPath\s*=/im.test(f.text)) push(ctx, { level: 'MEDIUM', module: '§26', campaign: null, path: p, code: 's26.hooks_path', ruleId: 's26-gitconfig:hooks', evidenceSha: f.sha256, locators: textLocators(f.text, /^\s*hooksPath\s*=/i) });
    }
    if (f.name === '.envrc' && /(curl|wget)[^|#\n]*\|\s*(ba|z)?sh|eval\s+"?\$\((curl|wget)/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§26', campaign: null, path: p, code: 's26.envrc_remote', ruleId: 's26-envrc', evidenceSha: f.sha256, locators: textLocators(f.text, /(curl|wget)[^|#]*\|\s*(ba|z)?sh|eval\s+\"?\$\((curl|wget)/) });
    }
    if (/(^|\/)LaunchAgents\/[^/]+\.plist$|(^|\/)LaunchDaemons\/[^/]+\.plist$/.test(p)) {
      const label = /<key>Label<\/key>\s*<string>([^<]*)<\/string>/.exec(f.text)?.[1];
      if (label && !label.includes('.')) push(ctx, { level: 'HIGH', module: '§30', campaign: null, path: p, code: 's30.random_label', params: { label }, ruleId: 's30-launchagent:label', evidenceSha: f.sha256 });
      if (/<string>(\/tmp\/|\/private\/tmp\/|\/Users\/Shared\/|\/var\/tmp\/)|<string>[^<]*\/\.[^/<]+\/[^<]*<\/string>/.test(f.text)) push(ctx, { level: 'HIGH', module: '§30', campaign: null, path: p, code: 's30.tmp_program', ruleId: 's30-launchagent:path', evidenceSha: f.sha256 });
    }
    if (/(^|\/)systemd\/user\/[^/]+\.service$|(^|\/)autostart\/[^/]+\.desktop$/.test(p) && /^\s*(ExecStart|ExecStartPre|Exec)\s*=[^#\n]*(\/tmp\/|\/dev\/shm\/|\/var\/tmp\/|\/\.[^/\s]+\/|curl|wget|base64|bash -c|sh -c)/m.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§31', campaign: 'ebpf-rootkit', path: p, code: 's31.autostart_suspicious', ruleId: 's31-autostart', evidenceSha: f.sha256, locators: textLocators(f.text, /^\s*(ExecStart|ExecStartPre|Exec)\s*=[^#]*(\/tmp\/|\/dev\/shm\/|\/var\/tmp\/|\/\.[^/\s]+\/|curl|wget|base64|bash -c|sh -c)/) });
    }
  }
}

export function ebpfRules(ctx: RuleCtx): void {
  ctx.checks.add('s40-loader').add('s40-names');
  for (const f of readable(ctx)) {
    if (!/\.(sh|bash|py|c|go|rs|service|conf)$/.test(f.name) && f.name.includes('.')) continue;
    if (/(>>?\s*\/etc\/ld\.so\.preload|bpftool\s+prog\s+(load|attach)|bpf_probe_write_user|BPF_PROG_LOAD|insmod\s|modprobe\s+-f)/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§40', campaign: 'ebpf-rootkit', path: f.relPath, code: 's40.preload_bpf_module', ruleId: 's40-loader', evidenceSha: f.sha256 });
    }
    if (/(quasar[ _-]?linux|\bQLNX\b|linkpro|voidlink)/i.test(f.text)) {
      push(ctx, { level: 'CRITICAL', module: '§40', campaign: 'ebpf-rootkit', path: f.relPath, code: 's40.rootkit_names', ruleId: 's40-names', evidenceSha: f.sha256 });
    }
  }
}

export function sigstoreRules(ctx: RuleCtx): void {
  ctx.checks.add('s28-cosign-key').add('s28-no-verify').add('s28-from-digest').add('s28-pull-always').add('s43-identity').add('s43-slsa').add('s48-provenance').add('s48-mismatch').add('s48-stale');
  for (const f of named(ctx, /^cosign\.key$/)) push(ctx, { level: 'HIGH', module: '§28', campaign: null, path: f.relPath, code: 's28.cosign_key', ruleId: 's28-cosign-key', evidenceSha: f.sha256 });
  for (const f of readable(ctx).filter((x) => /\.(sh|bash|ya?ml|mk)$|(^|\/)(Makefile|Jenkinsfile)$/.test(x.relPath))) {
    const joined = f.text.replace(/\\\r?\n/g, ' ');
    for (const line of joined.split(/\r?\n/)) {
      if (!/cosign\s+verify(-blob|-attestation|-blob-attestation)?(\s|$)/.test(line) || /--key([\s=]|$)/.test(line)) continue;
      if (!/--certificate-identity(-regexp)?[\s=]/.test(line)) {
        push(ctx, { level: 'HIGH', module: '§43', campaign: null, path: f.relPath, code: 's43.no_identity', ruleId: 's43-identity', evidenceSha: f.sha256 });
      } else if (!/--certificate-oidc-issuer(-regexp)?[\s=]/.test(line)) {
        push(ctx, { level: 'HIGH', module: '§43', campaign: null, path: f.relPath, code: 's43.no_issuer', ruleId: 's43-issuer', evidenceSha: f.sha256 });
      }
    }
    if (/slsa-verifier\s+verify-/.test(f.text) && !/--source-uri/.test(f.text)) push(ctx, { level: 'HIGH', module: '§43', campaign: null, path: f.relPath, code: 's43.no_source_uri', ruleId: 's43-slsa', evidenceSha: f.sha256 });
  }
  // §28 コンテナ署名（CLI check_s28）
  const builds = readable(ctx).some((x) => /(^|\/)(\.github\/workflows\/[^/]+\.ya?ml|Jenkinsfile)$|\.gitlab-ci\.yml$|\.sh$/.test(x.relPath) && /(docker\s+push|docker\/build-push-action|buildah\s+push|ko\s+publish)/.test(x.text));
  const verifies = readable(ctx).some((x) => /(\.ya?ml|\.sh)$|(^|\/)(Makefile|Jenkinsfile)$/.test(x.relPath) && /cosign\s+verify/.test(x.text));
  if (builds && !verifies) push(ctx, { level: 'MEDIUM', module: '§28', campaign: null, path: rootPath(ctx), code: 's28.no_verify', ruleId: 's28-no-verify' });
  for (const f of readable(ctx).filter((x) => DOCKERFILE.test(x.name))) {
    if (fromImages(f.text).some((img) => !/^(scratch|\$)/.test(img) && !img.includes('@sha256:'))) {
      push(ctx, { level: 'MEDIUM', module: '§28', campaign: null, path: f.relPath, code: 's28.from_digest', ruleId: 's28-from-digest', evidenceSha: f.sha256, kind: 'gha.unpinned' });
    }
  }
  for (const f of readable(ctx).filter((x) => /\.ya?ml$/.test(x.name))) {
    if (/imagePullPolicy:\s*Always/.test(f.text) && !/image:[ \t]*[^\s]+@sha256:/.test(f.text)) {
      push(ctx, { level: 'MEDIUM', module: '§28', campaign: null, path: f.relPath, code: 's28.pull_always', ruleId: 's28-pull-always', evidenceSha: f.sha256, kind: 'gha.unpinned' });
    }
  }

  // §48 SBOM 整合性（CLI check_s48。同じディレクトリ配下のロックファイル由来の依存と突合）
  const sboms = named(ctx, /(\.spdx\.json|\.cdx\.json|^bom\.json$|^sbom\.json$|\.spdx$|^cyclonedx\.json$)/);
  if (!sboms.length) return;
  const prov = named(ctx, /(\.intoto\.jsonl|^provenance\.json$|\.provenance\.json$|\.layout$)/).length > 0;
  const verify = readable(ctx).some((x) => /\.(ya?ml|sh)$/.test(x.name) && /(cosign\s+verify-attestation|slsa-verifier\s+verify-artifact|in-toto-verify)/.test(x.text));
  const deps = collectDeps(ctx);
  for (const f of sboms) {
    if (f.text === null) continue;
    let j: Record<string, unknown>;
    const sbom: [string, string][] = [];
    try {
      const v = JSON.parse(f.text.replace(/^﻿/, '')) as unknown;
      if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('not object');
      j = v as Record<string, unknown>;
      const str = (x: unknown) => (x === undefined || x === null || x === false ? '' : typeof x === 'string' ? x : JSON.stringify(x));
      for (const [key, vk] of [['components', 'version'], ['packages', 'versionInfo']] as const) {
        const arr = j[key];
        if (Array.isArray(arr)) for (const c of arr) if (c && typeof c === 'object') sbom.push([str((c as Record<string, unknown>)['name']), str((c as Record<string, unknown>)[vk])]);
      }
    } catch {
      ctx.errors.push({ module: '§48', reason: `sbom_parse_failed:${f.relPath}` });
      continue;
    }
    const meta = j['metadata'] as Record<string, unknown> | undefined;
    const ci = j['creationInfo'] as Record<string, unknown> | undefined;
    const created = (meta && typeof meta === 'object' ? meta['timestamp'] : undefined) ?? (ci && typeof ci === 'object' ? ci['created'] : undefined);
    const dir = f.relPath.includes('/') ? f.relPath.slice(0, f.relPath.lastIndexOf('/') + 1) : '';
    const under = deps.filter((d) => d.path.startsWith(dir));
    const lock = [...new Set(under.filter((d) => (d.eco === 'npm' || d.eco === 'pypi') && !/\/node_modules\/.*\/package\.json$/.test('/' + d.path)).map((d) => `${d.name}\t${d.version}`))].map((x) => x.split('\t') as [string, string]);
    if (!lock.length) continue;
    const sbomNames = new Set(sbom.map((x) => x[0]));
    const uniqSbom = [...new Set(sbom.map((x) => x.join('\t')))].map((x) => x.split('\t') as [string, string]);
    const missing = new Set(lock.map((x) => x[0]).filter((n) => !sbomNames.has(n))).size;
    let mism = 0;
    for (const [n, v] of lock) for (const [sn, sv] of uniqSbom) if (n === sn && v !== sv) mism++;
    if (missing > 0 || mism > 0) push(ctx, { level: 'HIGH', module: '§48', campaign: null, path: f.relPath, code: 's48.sbom_mismatch', params: { mismatched: mism, missing }, ruleId: 's48-mismatch', evidenceSha: f.sha256 });
    const ce = typeof created === 'string' && created ? Date.parse(created) : NaN;
    if (!Number.isNaN(ce)) {
      const stale = [...new Set(under.map((d) => d.path))].some((p) => { const lf = ctx.byPath.get(p); return !!lf && Math.floor(lf.lastModified / 1000) > Math.floor(ce / 1000) + 60; });
      if (stale) push(ctx, { level: 'MEDIUM', module: '§48', campaign: null, path: f.relPath, code: 's48.sbom_older', params: { created: created as string }, ruleId: 's48-stale', evidenceSha: f.sha256 });
    }
  }
  if (!prov && !verify) {
    push(ctx, { level: 'MEDIUM', module: '§48', campaign: null, path: rootPath(ctx), code: 's48.no_provenance', ruleId: 's48-provenance' });
  }
}

/** §8 クラウド/コンテナ（CLI check_s8）: .env ファイル、秘密鍵、Dockerfile の USER root・浮動タグ、docker.sock のマウント。 */
export function containerRules(ctx: RuleCtx): void {
  ctx.checks.add('s8-env').add('s8-private-key').add('s8-dockerfile').add('s8-docker-sock');
  for (const f of ctx.files) {
    if (/^\.env(\.[A-Za-z0-9_-]+)?$/.test(f.name) && !/\.env\.(example|sample|template|dist)$/.test(f.name)) {
      push(ctx, { level: 'MEDIUM', module: '§8', campaign: null, path: f.relPath, code: 's8.env_file', ruleId: 's8-env' });
    }
  }
  for (const f of readable(ctx)) {
    if (/^(id_rsa|id_dsa|id_ecdsa|id_ed25519|.*\.pem|.*\.key|.*\.p12|.*\.pfx)$/.test(f.name) && f.text.includes('PRIVATE KEY')) {
      push(ctx, { level: 'HIGH', module: '§8', campaign: null, path: f.relPath, code: 's8.private_key', ruleId: 's8-private-key', evidenceSha: f.sha256 });
    }
    if (DOCKERFILE.test(f.name)) {
      if (/^[ \t]*USER[ \t]+(root|0)([ \t\r]|$)/im.test(f.text)) push(ctx, { level: 'MEDIUM', module: '§8', campaign: null, path: f.relPath, code: 's8.user_root', ruleId: 's8-dockerfile:root', evidenceSha: f.sha256 });
      for (const img of fromImages(f.text)) {
        if (img === 'scratch' || img.startsWith('$') || img.includes('@sha256:')) continue;
        if (img.endsWith(':latest') || !img.slice(img.lastIndexOf('/') + 1).includes(':')) {
          push(ctx, { level: 'MEDIUM', module: '§8', campaign: null, path: f.relPath, code: 's8.floating_image', params: { image: img }, ruleId: `s8-dockerfile:floating:${img}`, evidenceSha: f.sha256 });
        }
      }
    }
    if (/\.(ya?ml|json)$/.test(f.name) && /\/var\/run\/docker\.sock|\/run\/docker\.sock/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§8', campaign: null, path: f.relPath, code: 's8.docker_sock', ruleId: 's8-docker-sock', evidenceSha: f.sha256 });
    }
  }
}

const DOCKERFILE = /^(Dockerfile.*|.*\.dockerfile)$/;

/** Dockerfile の FROM 行の 2 番目のフィールド（CLI の grep -i '^FROM' | awk '{print $2}' と同じ。空のフィールドは除く）。 */
function fromImages(text: string): string[] {
  return text.split(/\r?\n/).filter((l) => /^\s*FROM\s+/i.test(l)).map((l) => l.trim().split(/\s+/)[1] ?? '').filter(Boolean);
}

/** 投入フォルダ自体を指す path（CLI の $ROOT 相当。最上位ディレクトリ名、無ければ null）。 */
function rootPath(ctx: RuleCtx): string | null {
  return ctx.root || null;
}

export function credentialRules(ctx: RuleCtx): void {
  ctx.checks.add('s47-github-token').add('s47-history-export');
  for (const f of readable(ctx)) {
    if (/(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})/.test(f.text)) {
      push(ctx, { level: 'CRITICAL', module: '§47', campaign: null, path: f.relPath, code: 's47.github_token', ruleId: 's47-github-token', evidenceSha: f.sha256, kind: 'secret.token' });
    }
    if (/(^|\/)\.(bash|zsh)_history$/.test(f.relPath) && /export\s+[A-Za-z0-9_]*(_TOKEN|_KEY|_SECRET|PASSWORD)=/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§47', campaign: null, path: f.relPath, code: 's47.history_export', ruleId: 's47-history-export', evidenceSha: f.sha256, kind: 'secret.token' });
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
    if (/^Library\/LaunchAgents\/[^/]+\.plist$/.test(rel)) push(ctx, { level: 'INFO', module: '§10', campaign: null, path: f.relPath, code: 's10.launch_agent', ruleId: 's10-home:launchagent', evidenceSha: f.sha256 });
    if (/^\.(lesshst|viminfo|python_history|node_repl_history|mysql_history|psql_history)$/.test(rel)) push(ctx, { level: 'INFO', module: '§10', campaign: null, path: f.relPath, code: 's10.history_file', ruleId: 's10-home:history' });
  }
  const text = (rel: string) => at(rel)?.text ?? '';
  const rc = HOME_RC_FILES.map(text).join('\n');
  if (!/^\s*ignore-scripts\s*=\s*true/m.test(text('.npmrc'))) push(ctx, { level: 'MEDIUM', module: '§12', campaign: null, path: `${prefix}.npmrc`, code: 's12.npm_ignore_scripts', ruleId: 's12-vaccines:npm' });
  if (!/PYTHONNOUSERSITE=1/.test(rc)) push(ctx, { level: 'MEDIUM', module: '§12', campaign: null, path: null, code: 's12.pythonnousersite', ruleId: 's12-vaccines:pythonnousersite' });
  const pipConf = ['.config/pip/pip.conf', '.pip/pip.conf', 'Library/Application Support/pip/pip.conf'].some((p) => /^\s*require-virtualenv\s*=\s*(true|1)/m.test(text(p)));
  if (!/PIP_REQUIRE_VIRTUALENV=(true|1)/.test(rc) && !pipConf) push(ctx, { level: 'MEDIUM', module: '§12', campaign: null, path: null, code: 's12.pip_require_virtualenv', ruleId: 's12-vaccines:pip' });
}
