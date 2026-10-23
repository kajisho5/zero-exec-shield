# Normal form of tests/expected-codes/<fixture>.json (findings 1.2 message codes, the second parity layer with the UI).
#   One sorted list of {level, module, campaign, path, code, params}. Paths and path-valued params are relative to the
#   fixture ("." for the fixture itself), like tests/expected; findings under the shared HOME ($h) are left out because
#   they depend on the environment. Used by tests/gen-expected-codes.sh (writes) and tests/run-tests.sh (compares).
def rel: if . == null then null elif . == $rr then "." else ltrimstr($r) end;
[ .findings[]
  | select(((.path // "") | startswith($h)) | not)
  | { level, module, campaign, path: (.path | rel), code, params: (.params | map_values(rel)) } ]
| sort_by([.module, .level, (.campaign // ""), (.path // ""), .code, (.params | tojson)])
