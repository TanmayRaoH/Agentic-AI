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
