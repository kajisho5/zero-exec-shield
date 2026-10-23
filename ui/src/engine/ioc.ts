// rules/ioc.json をビルド時にバンドルへ取り込む（単一の真実の源。再ビルドで最新の IoC が反映される）。
import raw from '../../../rules/ioc.json';

export interface IocPackage {
  campaign: string;
  eco: string;
  name: string;
  match?: string;
  bad_versions?: string[];
  safe_version?: string | null;
  note?: string;
}

export interface SkillPactRules {
  contract_filenames: string[];
  schema_versions: string[];
  effects: string[];
  levels: string[];
  policy_files: string[];
  decision_values: string[];
  risk_flags: string[];
  destructive_markers: string[];
  persistence_markers: string[];
  trust_model: { l3_means: string; l3_does_not_mean: string; diff_anomaly_detection?: { threshold?: number } };
  prose_claims: { claim: string; patterns: string[]; forbids: string[] }[];
  observed_effect_patterns: Record<string, string[]>;
  l2_record_filenames: string[];
  signature_filenames: string[];
  script_extensions: string[];
}

export interface InfraCve {
  id: string;
  cvss?: number | null;
  fixed?: string[];
  severity?: string;
  kev?: boolean;
  /** 個別判定のある製品に追記した CVE を汎用判定の対象にする */
  generic?: boolean;
}

export interface Infrastructure {
  id: string;
  generic?: boolean;
  image_patterns?: string[];
  binary?: string;
  cves: InfraCve[];
}

/** 収集インテル（5.2.2）。CLI の intel_* 関数と同じデータ */
export interface IntelDb {
  files?: { campaign: string; severity?: string; sha256?: string[]; names?: string[]; name_severity?: string }[];
  network?: { campaign: string; domains?: string[]; ips?: string[]; urls?: string[]; legit_infra?: string[] }[];
  actions?: { campaign: string; action: string; severity?: string; bad_refs?: string[]; safe_refs?: string[] }[];
  workflow_strings?: { campaign: string; severity?: string; strings?: string[] }[];
  strings?: { campaign: string; module: string; severity?: string; file_regex?: string; strings?: string[] }[];
  extensions?: { campaign: string; eco: string; severity?: string; ids?: string[]; bad_versions?: string[] }[];
  host?: { campaign: string; severity?: string; paths?: string[]; launch_labels?: string[]; systemd_units?: string[]; process_names?: string[] }[];
  apps?: { campaign: string; bundle: string; cve: string; severity?: string; fixed: string }[];
}

export interface EmudhraRules {
  fixed?: { node?: string[]; java?: string[]; java8_update?: number; deno?: string[]; [k: string]: unknown };
  os_ca_certificates?: { ubuntu_min_upstream?: string; alpine?: string; [k: string]: unknown };
  [k: string]: unknown;
}

export interface IocDb {
  incident_bundle: string;
  packages: IocPackage[];
  infrastructures?: Infrastructure[];
  intel?: IntelDb;
  emudhra?: EmudhraRules;
  runtime_minimums?: { certifi?: string; [k: string]: unknown };
  worm_iocs: {
    chaindrop: { files: string[]; preinstall: string; hashes: { sha256: Record<string, string[]> }; domains: string[]; eth_contracts?: string[]; legit_infra?: string[] };
    teampcp: { c2_ip: string[]; c2_domains: string[]; legit_infra?: string[] };
    post_shaihulud: { binaries: string[]; masquerade: string[] };
    [k: string]: unknown;
  };
  mcp_poisoning: {
    symjack: { target_configs: string[]; decoy_name_patterns: string[] };
    runtime_gate: { injection_phrases: string[] };
    suspicious_commands: string[];
    [k: string]: unknown;
  };
  github_actions: { known_compromised: { action: string; versions: string[]; safe_tags?: string[] }[]; [k: string]: unknown };
  browser_extensions: { dangerous_permissions: string[]; dangerous_matches: string[]; official_update_urls: string[]; known_campaigns: { name: string }[] };
  build_hooks: { py_build_backend_safe: string[]; [k: string]: unknown };
  model_supply_chain: { risky_ext: string[]; [k: string]: unknown };
  ai_coding_assistant: { instruction_files: string[]; [k: string]: unknown };
  skillpact: SkillPactRules;
  markers: string[];
  malicious_files: string[];
  malicious_files_campaign: Record<string, string>;
  process_signatures: string[];
  payment_sdks: string[];
  [k: string]: unknown;
}

export const IOC = raw as unknown as IocDb;
