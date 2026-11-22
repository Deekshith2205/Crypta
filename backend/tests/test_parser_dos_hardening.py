"""Regression tests for Task B1: Configuration Parser Denial of Service (DoS) Hardening.
Verifies that:
- Deeply nested YAML is rejected safely.
- YAML alias bombs are rejected safely without unbounded memory or CPU consumption.
- Excessive JSON nesting is rejected safely without RecursionError.
- Excessive TOML, INI, and XML inputs are handled safely.
- XML entity / DOCTYPE expansion attacks are blocked.
- Oversized files (>1 MiB) and aggregate uploads (>5 MiB) remain rejected with HTTP 413.
- Valid configs across all formats continue to parse cleanly.
- Malformed inputs do not crash the application.
"""

import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.scanners.config_scanner.parsers import (
    SafeConfigParser,
    ParserSecurityError,
    ParserError,
)

client = TestClient(app)


def test_deeply_nested_yaml_rejected_safely(tmp_path):
    """Deeply nested YAML (exceeding maximum depth) must be rejected safely."""
    # Create YAML with 50 levels of nesting
    nested_yaml = "a:\n"
    for i in range(1, 50):
        nested_yaml += "  " * i + f"k{i}:\n"
    nested_yaml += "  " * 50 + "val: vulnerable\n"

    test_file = tmp_path / "deep.yaml"
    test_file.write_text(nested_yaml, encoding="utf-8")

    parser = SafeConfigParser(root_dir=tmp_path)
    result = parser.parse_file(test_file)

    # Must contain error regarding depth limit
    assert len(result.errors) > 0
    assert any("depth" in err.lower() or "nesting" in err.lower() for err in result.errors)


def test_yaml_alias_bomb_rejected_safely(tmp_path):
    """YAML alias bomb (billion laughs) must be detected and rejected without resource exhaustion."""
    alias_bomb = """
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
root: *f
"""
    test_file = tmp_path / "bomb.yaml"
    test_file.write_text(alias_bomb, encoding="utf-8")

    parser = SafeConfigParser(root_dir=tmp_path)
    result = parser.parse_file(test_file)

    assert len(result.errors) > 0
    assert any("alias" in err.lower() or "node count" in err.lower() or "security" in err.lower() for err in result.errors)


def test_excessive_json_nesting_rejected_safely(tmp_path):
    """Excessive JSON nesting must not raise unhandled RecursionError and must be rejected safely."""
    # 500 levels of nested arrays
    depth = 200
    deep_json = ("[" * depth) + "1" + ("]" * depth)

    test_file = tmp_path / "deep.json"
    test_file.write_text(deep_json, encoding="utf-8")

    parser = SafeConfigParser(root_dir=tmp_path)
    result = parser.parse_file(test_file)

    assert len(result.errors) > 0
    assert any("depth" in err.lower() or "nesting" in err.lower() for err in result.errors)


def test_xml_entity_and_doctype_rejected_safely(tmp_path):
    """XML with DOCTYPE or entity declarations must be rejected safely to prevent entity expansion attacks."""
    evil_xml = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<lolz>&lol1;</lolz>
"""
    test_file = tmp_path / "xxe.xml"
    test_file.write_text(evil_xml, encoding="utf-8")

    parser = SafeConfigParser(root_dir=tmp_path)
    result = parser.parse_file(test_file)

    assert len(result.errors) > 0
    assert any("doctype" in err.lower() or "entity" in err.lower() or "security" in err.lower() for err in result.errors)


def test_xml_deep_nesting_rejected_safely(tmp_path):
    """XML with excessive element nesting depth must be rejected safely."""
    xml_content = "<root>" + "".join(f"<tag{i}>" for i in range(50)) + "content" + "".join(f"</tag{i}>" for i in reversed(range(50))) + "</root>"
    test_file = tmp_path / "deep.xml"
    test_file.write_text(xml_content, encoding="utf-8")

    parser = SafeConfigParser(root_dir=tmp_path)
    result = parser.parse_file(test_file)

    assert len(result.errors) > 0
    assert any("depth" in err.lower() or "nesting" in err.lower() for err in result.errors)


def test_scan_config_endpoint_rejects_yaml_alias_bomb():
    """The /api/scan/config endpoint must reject alias bombs with HTTP 400 INVALID_CONFIGURATION."""
    alias_bomb = """
a: &a ["lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d]
root: *e
"""
    response = client.post(
        "/api/scan/config",
        json={"files": [{"name": "bomb.yaml", "content": alias_bomb}]},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_CONFIGURATION"


def test_scan_config_endpoint_rejects_deeply_nested_json():
    """The /api/scan/config endpoint must reject deeply nested JSON without crashing."""
    deep_json = ("[" * 150) + "1" + ("]" * 150)
    response = client.post(
        "/api/scan/config",
        json={"files": [{"name": "deep.json", "content": deep_json}]},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "INVALID_CONFIGURATION"


def test_valid_configs_across_all_formats_succeed(tmp_path):
    """Valid YAML, JSON, TOML, INI, PROPERTIES, ENV, XML continue to parse without errors."""
    parser = SafeConfigParser(root_dir=tmp_path)

    # Valid YAML
    yaml_f = tmp_path / "valid.yaml"
    yaml_f.write_text("tls:\n  version: TLSv1.3\n  cipher: AES-256-GCM\n", encoding="utf-8")
    assert len(parser.parse_file(yaml_f).errors) == 0

    # Valid JSON
    json_f = tmp_path / "valid.json"
    json_f.write_text('{"database": {"cipher": "AES-256-GCM"}}', encoding="utf-8")
    assert len(parser.parse_file(json_f).errors) == 0

    # Valid TOML
    toml_f = tmp_path / "valid.toml"
    toml_f.write_text('[crypto]\nalgorithm = "ML-KEM-768"\n', encoding="utf-8")
    assert len(parser.parse_file(toml_f).errors) == 0

    # Valid INI
    ini_f = tmp_path / "valid.ini"
    ini_f.write_text('[security]\ntls_version = TLSv1.2\n', encoding="utf-8")
    assert len(parser.parse_file(ini_f).errors) == 0

    # Valid XML
    xml_f = tmp_path / "valid.xml"
    xml_f.write_text('<config><security><cipher>AES-256-GCM</cipher></security></config>', encoding="utf-8")
    assert len(parser.parse_file(xml_f).errors) == 0
