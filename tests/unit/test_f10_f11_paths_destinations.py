"""Path and command safety (F10) and the destination allowlist (F11)."""
import os
from pathlib import Path

import pytest

from firewall import destinations, paths
from firewall.config import ToolsConfig
from firewall.models import Grant
from firewall.registry import Registry

TOOLS = ToolsConfig.model_validate({"tools": {
    "fs_read": {"labels": ["private"], "reviewed": True, "arg_kinds": {"path": "path"}, "path_roots": ["./sandbox"]},
    "fs_write": {"reviewed": True, "risk": "high", "arg_kinds": {"path": "path"}, "path_roots": ["./sandbox/out"]},
    "run": {"reviewed": True, "risk": "high", "arg_kinds": {"command": "command"}, "commands": ["ls", "cat"]},
    "run_shell": {"reviewed": True, "risk": "high", "arg_kinds": {"command": "command"}, "commands": ["ls"],
                  "allow_shell": True},
    "run_none": {"reviewed": True, "risk": "high", "arg_kinds": {"command": "command"}},
    "fetch": {"labels": ["sink"], "reviewed": True, "arg_kinds": {"url": "url"}, "dest_arg": "url"},
    "mail": {"labels": ["sink"], "reviewed": True, "arg_kinds": {"to": "email"}, "dest_arg": "to"},
    "host_sink": {"labels": ["sink"], "reviewed": True, "dest_arg": "host"},
    "open_sink": {"labels": ["sink"], "reviewed": True, "arg_kinds": {"to": "email"}, "dest_arg": "to"},
    "plain": {"reviewed": True},
}})
REG = Registry(TOOLS)


def grant(paths_=("./sandbox",), dests=()):
    return Grant(id="g", task="", allowed_tools=[], allowed_destinations=list(dests), allowed_paths=list(paths_),
                 max_calls=5, used_calls=0, max_sessions=1, expires_at="", approval_required_for=[], status="active")


@pytest.fixture
def world(tmp_path):
    (tmp_path / "sandbox" / "out").mkdir(parents=True)
    (tmp_path / "sandbox" / "docs").mkdir()
    (tmp_path / "sandbox" / "docs" / "a.txt").write_text("a")
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_text("root")
    (tmp_path / "outside").mkdir()
    return tmp_path


def make_link(target: Path, link: Path) -> None:
    """Symlink, or an NTFS junction on Windows machines without the symlink privilege."""
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        if os.name != "nt":
            pytest.skip("cannot create symlinks here")
        import subprocess

        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=False, capture_output=True)
        if r.returncode != 0:
            pytest.skip("cannot create symlinks or junctions here")


def check(tool, args, g=None, base=None):
    return paths.check_paths(REG.meta(tool), args, g or grant(), base)


# ---------------- F10 paths ----------------
@pytest.mark.parametrize("p", ["./sandbox/docs/a.txt", "sandbox/docs/a.txt", "./sandbox/new.txt", "./sandbox/./docs/a.txt",
                               "./sandbox/out/deep/er/file.txt"])
def test_f10_paths_inside_root_and_grant_pass(world, p):
    assert check("fs_read", {"path": p}, base=world) is None


@pytest.mark.parametrize("p, why", [
    ("./sandbox/../etc/passwd", "dot-dot"),
    ("../etc/passwd", "dot-dot"),
    ("./sandbox/docs/../../etc/passwd", "dot-dot"),
    ("./sandbox\\..\\etc\\passwd", "dot-dot"),
    ("./sandbox/%2e%2e/etc/passwd", "encoded"),
    ("./sandbox/%252e%252e/etc/passwd", "encoded"),
    ("..%2fetc%2fpasswd", "encoded"),
    ("./sandbox/a\0.txt", "null"),
    ("~/secrets.txt", "expansion"),
    ("./sandbox/$HOME/x", "expansion"),
    ("./outside/target.txt", "outside the tool's allowed roots"),
    ("./etc/passwd", "outside the tool's allowed roots"),
    ("", "outside the tool's allowed roots"),
])
def test_f10_attack_paths_are_violations(world, p, why):
    v = check("fs_read", {"path": p}, base=world)
    assert v is not None and v.reason_codes == ["PATH_VIOLATION"], p
    assert why in v.detail["reason"], (p, v.detail)


def test_f10_absolute_system_path_is_a_violation(world):
    for p in ("/etc/passwd", str(world / "etc" / "passwd"), "C:\\Windows\\win.ini"):
        v = check("fs_read", {"path": p}, base=world)
        assert v is not None and v.reason_codes == ["PATH_VIOLATION"], p


def test_f10_absolute_path_inside_the_root_is_fine(world):
    assert check("fs_read", {"path": str(world / "sandbox" / "docs" / "a.txt")}, base=world) is None


def test_f10_non_string_path_is_a_violation(world):
    for bad in (5, ["./sandbox/a"], {"p": 1}):
        assert check("fs_read", {"path": bad}, base=world).reason_codes == ["PATH_VIOLATION"]


def test_f10_tool_root_and_grant_paths_must_both_allow(world):
    # inside the tool's root (sandbox/out) and inside the grant
    assert check("fs_write", {"path": "./sandbox/out/x.txt"}, grant(("./sandbox",)), world) is None
    # inside the grant but outside the tool's root
    v = check("fs_write", {"path": "./sandbox/docs/a.txt"}, grant(("./sandbox",)), world)
    assert v.detail["reason"] == "outside the tool's allowed roots"
    # inside the tool's root but the grant only covers another folder
    v = check("fs_read", {"path": "./sandbox/docs/a.txt"}, grant(("./sandbox/out",)), world)
    assert v.detail["reason"] == "outside the grant's allowed paths"
    # a grant with no paths allows no path argument at all
    assert check("fs_read", {"path": "./sandbox/docs/a.txt"}, grant(()), world) is not None


def test_f10_symlink_escape_is_blocked(world):
    make_link(world / "etc", world / "sandbox" / "docs" / "escape")
    v = check("fs_read", {"path": "./sandbox/docs/escape/passwd"}, base=world)
    assert v is not None and v.reason_codes == ["PATH_VIOLATION"]


def test_f10_symlink_inside_the_root_is_allowed(world):
    make_link(world / "sandbox" / "docs", world / "sandbox" / "alias")
    assert check("fs_read", {"path": "./sandbox/alias/a.txt"}, base=world) is None


def test_f10_missing_argument_and_other_kinds_are_ignored(world):
    assert check("fs_read", {}, base=world) is None
    assert check("plain", {"path": "../../etc/passwd"}, base=world) is None  # not a path argument for this tool


# ---------------- F10 commands ----------------
@pytest.mark.parametrize("cmd", ["ls", "ls -la ./sandbox", "cat ./sandbox/readme.txt", "cat 'a file.txt'"])
def test_f10_allowlisted_commands_pass(cmd):
    assert check("run", {"command": cmd}) is None


@pytest.mark.parametrize("cmd", [
    "ls; cat /etc/passwd", "ls | cat", "ls & cat", "ls && cat", "ls $(whoami)", "ls `whoami`", "ls > out.txt",
    "ls < in.txt", "ls\ncat /etc/passwd", "ls\r\ncat x", "ls $HOME", "ls ${HOME}",
])
def test_f10_every_shell_metacharacter_is_a_violation(cmd):
    v = check("run", {"command": cmd})
    assert v is not None and v.reason_codes == ["COMMAND_VIOLATION"] and "metacharacter" in v.detail["reason"]


@pytest.mark.parametrize("cmd", ["rm -rf /", "curl http://x", "/bin/ls", "LS", "", "   ", "ls 'unclosed"])
def test_f10_commands_outside_the_allowlist_or_malformed_are_violations(cmd):
    v = check("run", {"command": cmd})
    assert v is not None and v.reason_codes == ["COMMAND_VIOLATION"]


def test_f10_allow_shell_permits_metacharacters_but_not_other_commands():
    assert check("run_shell", {"command": "ls | cat"}) is None
    assert check("run_shell", {"command": "rm -rf /"}).reason_codes == ["COMMAND_VIOLATION"]


def test_f10_command_tool_without_allowlist_denies_everything():
    assert check("run_none", {"command": "ls"}).reason_codes == ["COMMAND_VIOLATION"]


# ---------------- F11 destinations ----------------
def dest(tool, args, dests=("docs.example.com",)):
    return destinations.check_destination(REG.meta(tool), args, grant(dests=dests))


@pytest.mark.parametrize("url", [
    "https://docs.example.com/guide", "http://docs.example.com", "https://DOCS.Example.COM/x?y=1",
    "https://docs.example.com:8443/a", "https://docs.example.com./a",
])
def test_f11_allowed_urls(url):
    assert dest("fetch", {"url": url}) is None


@pytest.mark.parametrize("url, why", [
    ("https://docs.example.com.evil.example/", "not in allowed_destinations"),  # lookalike
    ("https://evildocs.example.com.attacker.example/", "not in allowed_destinations"),
    ("https://notdocs.example.com/", "not in allowed_destinations"),
    ("https://sub.docs.example.com/", "not in allowed_destinations"),  # no wildcard entry
    ("https://docs.example.com@evil.example/", "userinfo"),
    ("https://evil.example@docs.example.com/", "userinfo"),
    ("https://user:pw@docs.example.com/", "userinfo"),
    ("https://docs.example.com\\@evil.example/", "userinfo"),
    ("ftp://docs.example.com/", "scheme"),
    ("file:///etc/passwd", "scheme"),
    ("javascript:alert(1)", "scheme"),
    ("//docs.example.com/x", "scheme"),
    ("docs.example.com/x", "scheme"),
    ("https://docs.example.com:abc/", "invalid port"),
    ("https:///path", "userinfo or malformed"),
    ("", "destination argument missing"),
])
def test_f11_url_tricks_are_denied(url, why):
    v = dest("fetch", {"url": url})
    assert v is not None and v.reason_codes == ["DEST_NOT_ALLOWED"], url
    assert why in v.detail["reason"], (url, v.detail)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://127.1/", "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/",
    "http://[::1]/", "http://10.0.0.5/", "http://192.168.1.1/", "http://172.16.0.1/",
    "http://169.254.169.254/latest/meta-data/", "http://localhost/", "http://localhost:8800/", "http://app.localhost/",
    "http://8.8.8.8/",
])
def test_f11_ssrf_targets_are_denied_even_with_a_wildcard_grant(url):
    assert dest("fetch", {"url": url}, dests=("*.example.com", "docs.example.com")).reason_codes == ["DEST_NOT_ALLOWED"]


def test_f11_ip_literal_allowed_only_when_listed_exactly():
    assert dest("fetch", {"url": "http://10.0.0.5/x"}, dests=("10.0.0.5",)) is None
    assert dest("fetch", {"url": "http://10.0.0.6/x"}, dests=("10.0.0.5",)) is not None
    assert dest("fetch", {"url": "http://localhost:8800/"}, dests=("localhost",)) is None


def test_f11_wildcard_matches_subdomains_but_not_the_apex_or_lookalikes():
    d = ("*.example.com",)
    assert dest("fetch", {"url": "https://a.example.com/"}, d) is None
    assert dest("fetch", {"url": "https://a.b.example.com/"}, d) is None
    assert dest("fetch", {"url": "https://example.com/"}, d) is not None
    assert dest("fetch", {"url": "https://badexample.com/"}, d) is not None
    assert dest("fetch", {"url": "https://example.com.evil.example/"}, d) is not None
    assert dest("fetch", {"url": "https://a.example.com/"}, ("example.com",)) is not None  # exact entry, no wildcard


def test_f11_mixed_script_lookalike_hosts_are_denied():
    cyrillic_a = "docs.exаmple.com"  # the 'а' is Cyrillic
    assert dest("fetch", {"url": f"https://{cyrillic_a}/"}).reason_codes == ["DEST_NOT_ALLOWED"]
    assert "mixed-script" in dest("fetch", {"url": f"https://{cyrillic_a}/"}).detail["reason"]


def test_f11_idna_host_matches_its_punycode_entry():
    assert dest("fetch", {"url": "https://bücher.example/"}, ("xn--bcher-kva.example",)) is None
    assert dest("fetch", {"url": "https://bücher.example/"}, ("bücher.example",)) is None
    assert dest("fetch", {"url": "https://bucher.example/"}, ("xn--bcher-kva.example",)) is not None


@pytest.mark.parametrize("to", ["team@docs.example.com", "Team@DOCS.example.com", "Team <team@docs.example.com>",
                                "a@docs.example.com, b@docs.example.com"])
def test_f11_allowed_emails(to):
    assert dest("mail", {"to": to}) is None


@pytest.mark.parametrize("to", [
    "x@evil.example", "x@docs.example.com.evil.example", "a@docs.example.com, b@evil.example",
    "a@docs.example.com; b@evil.example", "a@b@docs.example.com", "docs.example.com", "nobody", "", "<>",
    "a@docs.example.com b@evil.example",
])
def test_f11_bad_emails_are_denied(to):
    assert dest("mail", {"to": to}).reason_codes == ["DEST_NOT_ALLOWED"], to


def test_f11_non_sink_tools_are_not_checked_and_sinks_without_dest_arg_are_denied():
    assert dest("plain", {"url": "http://127.0.0.1"}) is None
    no_dest = REG.meta("open_sink")
    no_dest.dest_arg = None
    assert destinations.check_destination(no_dest, {"to": "a@docs.example.com"}, grant(dests=("docs.example.com",))).reason_codes == [
        "DEST_NOT_ALLOWED"]


def test_f11_empty_allowlist_denies_every_destination():
    assert dest("fetch", {"url": "https://docs.example.com/"}, dests=()) is not None
    assert dest("mail", {"to": "a@docs.example.com"}, dests=()) is not None


def test_f11_unreviewed_tool_is_treated_as_a_sink():
    reg = Registry(ToolsConfig.model_validate({"tools": {"mystery": {"dest_arg": "to", "arg_kinds": {"to": "email"}}}}))
    v = destinations.check_destination(reg.meta("mystery"), {"to": "x@evil.example"}, grant(dests=("docs.example.com",)))
    assert v.reason_codes == ["DEST_NOT_ALLOWED"]


def test_f11_bare_hostname_destination():
    assert dest("host_sink", {"host": "docs.example.com"}) is None
    assert dest("host_sink", {"host": "docs.example.com:443"}) is None
    assert dest("host_sink", {"host": "evil.example"}) is not None


def test_f10_paths_module_uses_cwd_when_no_base_given(monkeypatch, world):
    monkeypatch.chdir(world)
    assert paths.check_paths(REG.meta("fs_read"), {"path": "./sandbox/docs/a.txt"}, grant()) is None
