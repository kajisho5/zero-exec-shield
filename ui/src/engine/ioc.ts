// Bundles rules/ioc.json at build time (the single source of truth; a rebuild picks up the latest IoCs).
import raw from '../../../rules/ioc.json';
import type { Effect } from './types';

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
  spec: { name: string; version: string; url: string; attribution: string; zes_support: string };
  contract_filename: string;
  contract_keys: string[];
  capability_keys: string[];
  contract_versions: string[];
  effects: Effect[];
  decision_values: string[];
  policy_versions: string[];
  policy_keys: string[];
  trust_model: { l3_means: string; l3_does_not_mean: string; zes_level: string };
  observed_effect_patterns: Record<string, string[]>;
  sensitive_read_patterns: string[];
  persistence_markers: string[];
  sensitive_scope_regex: string;
  broad_scopes: string[];
  ephemeral_scope_prefixes: string[];
  integrity: { default_exclude: string[]; protected: string[]; code_extensions: string[] };
  shell_fence_langs: string[];
  script_extensions: string[];
}

export interface InfraCve {
  id: string;
  cvss?: number | null;
  fixed?: string[];
  severity?: string;
  kev?: boolean;
  /** Makes CVEs appended to a product with its own evaluation subject to the generic evaluation */
  generic?: boolean;
}

export interface Infrastructure {
  id: string;
  generic?: boolean;
  image_patterns?: string[];
  binary?: string;
  cves: InfraCve[];
}

/** Collected intel (5.2.2). The same data as the intel_* functions of the CLI */
export interface IntelDb {
  files?: { campaign: string; severity?: string; sha256?: string[]; names?: string[]; name_severity?: string }[];
  network?: { campaign: string; domains?: string[]; ips?: string[]; urls?: string[]; legit_infra?: string[] }[];
  actions?: { campaign: string; action: string; severity?: string; bad_refs?: string[]; safe_refs?: string[] }[];
  workflow_strings?: { campaign: string; severity?: string; strings?: string[] }[];
  strings?: { campaign: string; module: string; severity?: string; file_regex?: string; strings?: string[] }[];
  extensions?: { campaign: string; eco: string; severity?: string; ids?: string[]; bad_versions?: string[] }[];
  host?: { campaign: string; severity?: string; paths?: string[]; file_names?: string[] | null; modified_files?: string[]; launch_labels?: string[]; systemd_units?: string[]; process_names?: string[] }[];
  apps?: { campaign: string; bundle: string; cve: string; severity?: string; fixed: string }[];
}

export interface EmudhraRules {
  fixed?: { node?: string[]; java?: string[]; java8_update?: number; deno?: string[]; [k: string]: unknown };
  os_ca_certificates?: { ubuntu_min_upstream?: string; alpine?: string; [k: string]: unknown };
  [k: string]: unknown;
}

/** PHP2Shell upstream fixed versions, old branches and vendor package fixed versions (the same tables as CLI php_status / php_distro_packages) */
export interface Php2ShellDistro {
  upstream_fixed?: string[];
  older_branches?: string[];
  packages?: { vendor: string; release: string; codename?: string; source_package: string; fixed: string; advisory?: string; url?: string }[];
  [k: string]: unknown;
}

export interface IocDb {
  incident_bundle: string;
  protected_hosts?: string[];
  php2shell_distro?: Php2ShellDistro;
  packages: IocPackage[];
  infrastructures?: Infrastructure[];
  intel?: IntelDb;
  emudhra?: EmudhraRules;
  runtime_minimums?: { certifi?: string; python?: string[]; [k: string]: unknown };
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
