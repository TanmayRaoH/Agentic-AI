from pathlib import Path

import pytest

from firewall.config import ConfigError, load_policy, load_tools, load_upstreams

ROOT = Path(__file__).resolve().parents[2]


def test_f23_shipped_configs_load():
    assert "notes_read" in load_tools(ROOT / "tools.yaml").tools
    assert load_policy(ROOT / "policy.yaml").defaults.mode == "enforce"
    assert len(load_upstreams(ROOT / "upstreams.yaml").upstreams) == 4


def test_f23_unknown_key_is_error(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("defaults: { bogus: 1 }\n")
    with pytest.raises(ConfigError, match="bogus"):
        load_policy(p)


def test_f23_sink_without_dest_arg_rejected(tmp_path):
    p = tmp_path / "tools.yaml"
    p.write_text("tools:\n  x: { labels: [sink], risk: high }\n")
    with pytest.raises(ConfigError, match="dest_arg"):
        load_tools(p)


def test_f23_path_kind_without_roots_rejected(tmp_path):
    p = tmp_path / "tools.yaml"
    p.write_text("tools:\n  x: { arg_kinds: { p: path } }\n")
    with pytest.raises(ConfigError, match="path_roots"):
        load_tools(p)


def test_f23_missing_file_message(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_tools(tmp_path / "nope.yaml")


# ---- Phase 3: every malformed-config case names the file, the key and a fix hint ----
@pytest.mark.parametrize("filename, loader, text, key, hint", [
    ("policy.yaml", load_policy, "defaults: { mode: observe }", "defaults.mode", "permitted values"),
    ("policy.yaml", load_policy, "defaults: { approval_timeout_s: soon }", "defaults.approval_timeout_s", "whole number"),
    ("policy.yaml", load_policy, "rules: [ { match: {}, action: allow } ]", "rules.0.action", "permitted values"),
    ("policy.yaml", load_policy, "rules: [ { match: { arg_regex: { a: '(' } }, action: deny } ]", "rules.0.match", "regular expression"),
    ("policy.yaml", load_policy, "rules: [ { match: { time_window: noon }, action: deny } ]", "rules.0.match", "time_window"),
    ("policy.yaml", load_policy, "rules: [ { action: deny } ]", "rules.0.match", "missing"),
    ("tools.yaml", load_tools, "tools: { t: { risk: extreme } }", "tools.t.risk", "permitted values"),
    ("tools.yaml", load_tools, "tools: { t: { labels: [secret] } }", "tools.t.labels.0", "permitted values"),
    ("tools.yaml", load_tools, "tools: { t: { colour: red } }", "tools.t.colour", "unknown key"),
    ("tools.yaml", load_tools, "tools: [a, b]", "tools", "mapping"),
    ("tools.yaml", load_tools, "nothing: here", "tools", "missing"),
    ("upstreams.yaml", load_upstreams, "upstreams: [ { name: a, transport: ftp } ]", "upstreams.0.transport", "permitted values"),
    ("upstreams.yaml", load_upstreams, "upstreams: [ { name: a, transport: http } ]", "upstreams.0", "url"),
    ("upstreams.yaml", load_upstreams, "upstreams: [ { transport: stdio, command: x } ]", "upstreams.0.name", "missing"),
])
def test_f23_malformed_config_names_file_key_and_fix(tmp_path, filename, loader, text, key, hint):
    p = tmp_path / filename
    p.write_text(text)
    with pytest.raises(ConfigError) as e:
        loader(p)
    msg = str(e.value)
    assert filename in msg, msg
    assert key in msg, msg
    assert hint in msg, msg
    assert "Fix:" in msg, msg


def test_f23_invalid_yaml_syntax_is_reported(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("defaults: [unclosed")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_policy(p)


def test_f23_config_version_changes_with_content(tmp_path):
    from firewall.config import config_version

    a = tmp_path / "a.yaml"
    a.write_text("x: 1")
    v1 = config_version(a)
    a.write_text("x: 2")
    assert v1 != config_version(a) and len(v1) == 12
