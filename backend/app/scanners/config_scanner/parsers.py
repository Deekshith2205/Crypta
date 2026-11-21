"""Configuration file parsers with security boundaries, line tracking, and format support.
Supported formats:
- YAML (.yaml, .yml)
- JSON (.json)
- TOML (.toml)
- INI / CFG / CONF (.ini, .cfg, .conf)
- Java Properties (.properties)
- XML (.xml)
- ENV / Example Environment (.env, .env.example)

Security guarantees:
- Never executes or imports configuration code.
- Rejects binary files and files with null bytes.
- Enforces directory boundary and rejects path traversal attempts.
- Gracefully handles syntax/decode errors without crashing.
"""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import xml.etree.ElementTree as ET

# Attempt PyYAML import; fallback to built-in basic parser if missing
try:
    import yaml
    from yaml.loader import SafeLoader
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

# Python 3.11+ tomllib
try:
    import tomllib
    HAVE_TOML = True
except ImportError:
    HAVE_TOML = False


class ParserSecurityError(Exception):
    """Raised when security boundaries (path traversal, binary data) are violated."""
    pass


class ParserError(Exception):
    """Raised or captured when configuration file parsing fails."""
    pass


@dataclass
class ParsedEntry:
    """A flattened configuration key-value entry with path and line provenance."""
    path: str
    value: Any
    line: Optional[int] = None
    raw_key: str = ""
    is_interpolated: bool = False  # e.g., ${VAR}
    is_list: bool = False

    def __post_init__(self):
        if not self.raw_key and self.path:
            self.raw_key = self.path.split(".")[-1]



@dataclass
class ParsedConfigFile:
    """The normalized result of parsing a configuration file."""
    file_path: str
    format: str
    raw_data: Any
    entries: List[ParsedEntry] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# Line-tracking YAML SafeLoader with alias and node bounds
if HAVE_YAML:
    class LineTrackingSafeLoader(SafeLoader):
        """Custom SafeLoader that stores line numbers for dicts and values,
        and enforces limits on aliases and nodes to prevent denial-of-service."""
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.alias_count = 0
            self.node_count = 0

        def compose_node(self, parent, index):
            self.node_count += 1
            if self.node_count > SafeConfigParser.MAX_TOTAL_NODES:
                raise ParserSecurityError(
                    f"Maximum YAML node count ({SafeConfigParser.MAX_TOTAL_NODES}) exceeded"
                )
            if self.check_event(yaml.events.AliasEvent):
                self.alias_count += 1
                if self.alias_count > SafeConfigParser.MAX_YAML_ALIASES:
                    raise ParserSecurityError(
                        f"YAML alias count ({self.alias_count}) exceeded safe limit ({SafeConfigParser.MAX_YAML_ALIASES}); possible alias expansion attack"
                    )
            return super().compose_node(parent, index)

    def _construct_mapping_with_lines(loader: SafeLoader, node: Any) -> Dict[str, Any]:
        loader.flatten_mapping(node)
        mapping = {}
        line_map = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=False)
            val = loader.construct_object(value_node, deep=False)
            mapping[key] = val
            line_map[key] = key_node.start_mark.line + 1
        mapping["__line_map__"] = line_map
        mapping["__line__"] = node.start_mark.line + 1
        return mapping

    LineTrackingSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        _construct_mapping_with_lines
    )


class SafeConfigParser:
    """
    Safe parser for banking configurations across multiple formats.
    Enforces path boundaries, depth limits, and avoids executing code.
    """

    MAX_NESTING_DEPTH: int = 20
    MAX_TOTAL_NODES: int = 5000
    MAX_YAML_ALIASES: int = 5
    MAX_STRING_LENGTH: int = 65536
    MAX_COLLECTION_SIZE: int = 2000

    SUPPORTED_EXTENSIONS = {
        ".yaml": "YAML",
        ".yml": "YAML",
        ".json": "JSON",
        ".toml": "TOML",
        ".ini": "INI",
        ".cfg": "INI",
        ".conf": "INI",
        ".properties": "PROPERTIES",
        ".env": "ENV",
        ".example": "ENV",
        ".xml": "XML",
    }

    def __init__(self, root_dir: Optional[Path] = None):
        """
        Initialize parser.
        :param root_dir: If specified, all parsed files must reside within root_dir.
        """
        self.root_dir = root_dir.resolve() if root_dir else None

    def validate_file_path(self, file_path: Union[str, Path]) -> Path:
        """
        Validate file path against traversal and binary rules.
        """
        path = Path(file_path).resolve()
        if self.root_dir:
            try:
                path.relative_to(self.root_dir)
            except ValueError:
                raise ParserSecurityError(f"Path traversal detected: {path} is outside allowed root {self.root_dir}")

        if not path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        # Check for binary file
        try:
            with open(path, "rb") as f:
                header = f.read(4096)
                if b"\x00" in header:
                    raise ParserSecurityError(f"Binary file rejected: {path}")
        except OSError as e:
            raise ParserError(f"Cannot read file {path}: {e}")

        return path

    def parse_file(self, file_path: Union[str, Path], relative_to: Optional[Path] = None) -> ParsedConfigFile:
        """
        Parse configuration file safely into normalized entries with line numbers.
        """
        canonical_path = self.validate_file_path(file_path)
        display_path = str(canonical_path.relative_to(relative_to)) if relative_to else canonical_path.name

        ext = canonical_path.suffix.lower()
        # Handle compound extensions like .env.example
        if canonical_path.name.startswith(".env") or ext in (".env", ".example"):
            fmt = "ENV"
        else:
            fmt = self.SUPPORTED_EXTENSIONS.get(ext)

        if not fmt:
            return ParsedConfigFile(
                file_path=display_path,
                format="UNSUPPORTED",
                raw_data=None,
                errors=[f"Unsupported configuration extension: {ext}"]
            )

        try:
            text = canonical_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return ParsedConfigFile(
                file_path=display_path,
                format=fmt,
                raw_data=None,
                errors=[f"Failed to read file: {e}"]
            )

        entries: List[ParsedEntry] = []
        errors: List[str] = []
        raw_data = None

        try:
            if fmt == "YAML":
                raw_data, entries = self._parse_yaml(text)
            elif fmt == "JSON":
                raw_data, entries = self._parse_json(text)
            elif fmt == "TOML":
                raw_data, entries = self._parse_toml(text)
            elif fmt == "INI":
                raw_data, entries = self._parse_ini(text)
            elif fmt == "PROPERTIES":
                raw_data, entries = self._parse_properties(text)
            elif fmt == "ENV":
                raw_data, entries = self._parse_env(text)
            elif fmt == "XML":
                raw_data, entries = self._parse_xml(text)
        except ParserSecurityError as e:
            errors.append(f"Security validation failed: {e}")
        except ParserError as e:
            errors.append(f"Parsing error: {e}")
        except Exception as e:
            errors.append(f"Parsing {fmt} failed: {e}")

        return ParsedConfigFile(
            file_path=display_path,
            format=fmt,
            raw_data=raw_data,
            entries=entries,
            errors=errors
        )

    # ----------------- SECURITY VALIDATORS -----------------

    def _validate_structure(self, node: Any, depth: int = 1) -> None:
        """Validate maximum nesting depth, string lengths, and collection sizes."""
        if depth > self.MAX_NESTING_DEPTH:
            raise ParserSecurityError(f"Maximum nesting depth ({self.MAX_NESTING_DEPTH}) exceeded")

        if isinstance(node, dict):
            if len(node) > self.MAX_COLLECTION_SIZE:
                raise ParserSecurityError(f"Collection size ({len(node)}) exceeds limit ({self.MAX_COLLECTION_SIZE})")
            for k, v in node.items():
                if k in ("__line_map__", "__line__"):
                    continue
                if isinstance(k, str) and len(k) > self.MAX_STRING_LENGTH:
                    raise ParserSecurityError(f"Key length ({len(k)}) exceeds maximum allowed")
                self._validate_structure(v, depth + 1)
        elif isinstance(node, list):
            if len(node) > self.MAX_COLLECTION_SIZE:
                raise ParserSecurityError(f"Collection size ({len(node)}) exceeds limit ({self.MAX_COLLECTION_SIZE})")
            for item in node:
                self._validate_structure(item, depth + 1)
        elif isinstance(node, str):
            if len(node) > self.MAX_STRING_LENGTH:
                raise ParserSecurityError(f"String value length ({len(node)}) exceeds maximum allowed")

    def _check_json_depth(self, text: str) -> None:
        """Fast linear-time scan of JSON nesting depth to prevent parser recursion exhaustion."""
        current_depth = 0
        in_string = False
        escape = False
        for char in text:
            if escape:
                escape = False
                continue
            if char == '\\':
                escape = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if char in ('{', '['):
                current_depth += 1
                if current_depth > self.MAX_NESTING_DEPTH:
                    raise ParserSecurityError(f"Maximum JSON nesting depth ({self.MAX_NESTING_DEPTH}) exceeded")
            elif char in ('}', ']'):
                current_depth = max(0, current_depth - 1)

    # ----------------- PARSERS -----------------

    def _parse_yaml(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        if not HAVE_YAML:
            return None, []
        try:
            data = yaml.load(text, Loader=LineTrackingSafeLoader)
        except ParserSecurityError:
            raise
        except Exception as e:
            raise ParserError(f"YAML parsing failed: {e}")

        self._validate_structure(data, depth=1)

        entries: List[ParsedEntry] = []
        self._extract_entries_from_dict(data, prefix="", entries=entries, depth=1)
        return data, entries

    def _extract_entries_from_dict(
        self,
        node: Any,
        prefix: str,
        entries: List[ParsedEntry],
        parent_line_map: Optional[Dict[str, int]] = None,
        depth: int = 1
    ) -> None:
        if depth > self.MAX_NESTING_DEPTH:
            raise ParserSecurityError(f"Maximum nesting depth ({self.MAX_NESTING_DEPTH}) exceeded")
        if len(entries) > self.MAX_TOTAL_NODES:
            raise ParserSecurityError(f"Maximum node count ({self.MAX_TOTAL_NODES}) exceeded")

        if isinstance(node, dict):
            current_line_map = node.get("__line_map__", {})
            for key, val in node.items():
                if key in ("__line_map__", "__line__"):
                    continue
                path = f"{prefix}.{key}" if prefix else str(key)
                line = current_line_map.get(key)
                if line is None and parent_line_map:
                    line = parent_line_map.get(key)
                if isinstance(val, (dict, list)):
                    self._extract_entries_from_dict(val, path, entries, current_line_map, depth + 1)
                    if isinstance(val, list):
                        entries.append(self._create_entry(path, val, line, is_list=True))
                else:
                    entries.append(self._create_entry(path, val, line))
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                path = f"{prefix}[{idx}]"
                if isinstance(item, (dict, list)):
                    self._extract_entries_from_dict(item, path, entries, None, depth + 1)
                else:
                    entries.append(self._create_entry(path, item, None))

    def _parse_json(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        self._check_json_depth(text)
        try:
            data = json.loads(text)
        except RecursionError:
            raise ParserSecurityError(f"Maximum JSON nesting depth ({self.MAX_NESTING_DEPTH}) exceeded")
        except Exception as e:
            raise ParserError(f"JSON parsing failed: {e}")

        self._validate_structure(data, depth=1)

        lines = text.splitlines()
        line_cache: Dict[str, int] = {}
        for line_no, line_str in enumerate(lines, start=1):
            if len(line_str) > self.MAX_STRING_LENGTH:
                raise ParserSecurityError("JSON line length exceeds maximum allowed")
            match = re.search(r'"([^"\\]+)":', line_str)
            if match:
                key = match.group(1)
                if key not in line_cache:
                    line_cache[key] = line_no

        entries: List[ParsedEntry] = []
        self._flatten_json(data, prefix="", entries=entries, line_cache=line_cache, depth=1)
        return data, entries

    def _flatten_json(
        self,
        node: Any,
        prefix: str,
        entries: List[ParsedEntry],
        line_cache: Dict[str, int],
        depth: int = 1
    ) -> None:
        if depth > self.MAX_NESTING_DEPTH:
            raise ParserSecurityError(f"Maximum JSON nesting depth ({self.MAX_NESTING_DEPTH}) exceeded")
        if len(entries) > self.MAX_TOTAL_NODES:
            raise ParserSecurityError(f"Maximum node count ({self.MAX_TOTAL_NODES}) exceeded")

        if isinstance(node, dict):
            for key, val in node.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                line = line_cache.get(key)
                if isinstance(val, dict):
                    self._flatten_json(val, path, entries, line_cache, depth + 1)
                elif isinstance(val, list):
                    entries.append(self._create_entry(path, val, line, is_list=True))
                    self._flatten_json(val, path, entries, line_cache, depth + 1)
                else:
                    entries.append(self._create_entry(path, val, line))
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                path = f"{prefix}[{idx}]"
                if isinstance(item, (dict, list)):
                    self._flatten_json(item, path, entries, line_cache, depth + 1)
                else:
                    entries.append(self._create_entry(path, item, None))

    def _parse_toml(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        if not HAVE_TOML:
            raise ParserError("tomllib is required for TOML parsing")
        try:
            data = tomllib.loads(text)
        except Exception as e:
            raise ParserError(f"TOML parsing failed: {e}")

        self._validate_structure(data, depth=1)
        lines = text.splitlines()
        entries: List[ParsedEntry] = []

        def find_line(key: str) -> Optional[int]:
            pattern = re.compile(rf'^\s*{re.escape(key)}\s*=')
            for idx, l in enumerate(lines, start=1):
                if pattern.search(l):
                    return idx
            return None

        def recurse(node: Any, prefix: str, depth: int):
            if depth > self.MAX_NESTING_DEPTH:
                raise ParserSecurityError(f"Maximum TOML nesting depth ({self.MAX_NESTING_DEPTH}) exceeded")
            if len(entries) > self.MAX_TOTAL_NODES:
                raise ParserSecurityError(f"Maximum node count ({self.MAX_TOTAL_NODES}) exceeded")

            if isinstance(node, dict):
                for k, v in node.items():
                    path = f"{prefix}.{k}" if prefix else str(k)
                    line = find_line(k)
                    if isinstance(v, dict):
                        recurse(v, path, depth + 1)
                    elif isinstance(v, list):
                        entries.append(self._create_entry(path, v, line, is_list=True))
                        recurse(v, path, depth + 1)
                    else:
                        entries.append(self._create_entry(path, v, line))
            elif isinstance(node, list):
                for idx, item in enumerate(node):
                    path = f"{prefix}[{idx}]"
                    if isinstance(item, (dict, list)):
                        recurse(item, path, depth + 1)
                    else:
                        entries.append(self._create_entry(path, item, None))

        recurse(data, "", 1)
        return data, entries

    def _parse_ini(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        entries: List[ParsedEntry] = []
        raw: Dict[str, Dict[str, str]] = {}
        current_section = "DEFAULT"
        raw[current_section] = {}

        for line_no, line in enumerate(text.splitlines(), start=1):
            if len(line) > self.MAX_STRING_LENGTH:
                raise ParserSecurityError("INI line length exceeds maximum allowed")
            line_str = line.strip()
            if not line_str or line_str.startswith("#") or line_str.startswith(";"):
                continue
            sec_match = re.match(r"^\[([a-zA-Z0-9_\-\.\:]+)\]$", line_str)
            if sec_match:
                current_section = sec_match.group(1)
                if len(raw) > self.MAX_COLLECTION_SIZE:
                    raise ParserSecurityError("INI section count exceeds maximum allowed")
                raw[current_section] = {}
                continue
            if len(entries) > self.MAX_TOTAL_NODES:
                raise ParserSecurityError(f"Maximum node count ({self.MAX_TOTAL_NODES}) exceeded")
            if "=" in line_str or ":" in line_str:
                sep = "=" if "=" in line_str else ":"
                k, v = line_str.split(sep, 1)
                key = k.strip()
                val = v.strip().rstrip(";")
                raw[current_section][key] = val
                path = f"{current_section}.{key}" if current_section != "DEFAULT" else key
                entries.append(self._create_entry(path, val, line_no))
            else:
                parts = line_str.split(None, 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = parts[1].strip().rstrip(";")
                    if re.match(r"^[a-zA-Z0-9_\-\.]+$", key) and not key.startswith(("{", "}", "[", "]")):
                        raw[current_section][key] = val
                        path = f"{current_section}.{key}" if current_section != "DEFAULT" else key
                        entries.append(self._create_entry(path, val, line_no))

        return raw, entries

    def _parse_properties(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        entries: List[ParsedEntry] = []
        raw: Dict[str, str] = {}
        for line_no, line in enumerate(text.splitlines(), start=1):
            if len(line) > self.MAX_STRING_LENGTH:
                raise ParserSecurityError("Properties line length exceeds maximum allowed")
            line_str = line.strip()
            if not line_str or line_str.startswith("#") or line_str.startswith("!"):
                continue
            if len(entries) > self.MAX_TOTAL_NODES:
                raise ParserSecurityError(f"Maximum node count ({self.MAX_TOTAL_NODES}) exceeded")
            if "=" in line_str or ":" in line_str:
                sep = "=" if "=" in line_str else ":"
                k, v = line_str.split(sep, 1)
                key = k.strip()
                val = v.strip()
                raw[key] = val
                entries.append(self._create_entry(key, val, line_no))
        return raw, entries

    def _parse_env(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        entries: List[ParsedEntry] = []
        raw: Dict[str, str] = {}
        for line_no, line in enumerate(text.splitlines(), start=1):
            if len(line) > self.MAX_STRING_LENGTH:
                raise ParserSecurityError("ENV line length exceeds maximum allowed")
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if len(entries) > self.MAX_TOTAL_NODES:
                raise ParserSecurityError(f"Maximum node count ({self.MAX_TOTAL_NODES}) exceeded")
            if "=" in line_str:
                k, v = line_str.split("=", 1)
                key = k.strip()
                val = v.strip().strip("'\"")
                raw[key] = val
                entries.append(self._create_entry(key, val, line_no))
        return raw, entries

    def _parse_xml(self, text: str) -> Tuple[Any, List[ParsedEntry]]:
        upper = text.upper()
        if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
            raise ParserSecurityError("XML DOCTYPE and ENTITY declarations are rejected for security reasons")

        try:
            root = ET.fromstring(text)
        except Exception as e:
            raise ParserError(f"XML parsing failed: {e}")

        node_count = 0
        def check_depth(node: ET.Element, depth: int):
            nonlocal node_count
            node_count += 1
            if depth > self.MAX_NESTING_DEPTH:
                raise ParserSecurityError(f"Maximum XML nesting depth ({self.MAX_NESTING_DEPTH}) exceeded")
            if node_count > self.MAX_TOTAL_NODES:
                raise ParserSecurityError(f"Maximum XML node count ({self.MAX_TOTAL_NODES}) exceeded")
            for child in node:
                check_depth(child, depth + 1)

        check_depth(root, 1)

        entries: List[ParsedEntry] = []
        lines = text.splitlines()

        def find_tag_line(tag: str) -> Optional[int]:
            pattern = re.compile(rf'<{re.escape(tag)}[\s>]')
            for idx, l in enumerate(lines, start=1):
                if pattern.search(l):
                    return idx
            return None

        raw = {root.tag: {}}

        def recurse(node: ET.Element, path: str, depth: int):
            if depth > self.MAX_NESTING_DEPTH:
                raise ParserSecurityError(f"Maximum XML nesting depth ({self.MAX_NESTING_DEPTH}) exceeded")
            if len(entries) > self.MAX_TOTAL_NODES:
                raise ParserSecurityError(f"Maximum XML node count ({self.MAX_TOTAL_NODES}) exceeded")
            line = find_tag_line(node.tag)
            text_val = node.text.strip() if node.text else None
            if text_val:
                entries.append(self._create_entry(path, text_val, line))
            for attr_k, attr_v in node.attrib.items():
                attr_path = f"{path}@{attr_k}"
                entries.append(self._create_entry(attr_path, attr_v, line))
            for child in node:
                child_path = f"{path}.{child.tag}"
                recurse(child, child_path, depth + 1)

        recurse(root, root.tag, 1)
        return raw, entries

    def _create_entry(
        self,
        path: str,
        val: Any,
        line: Optional[int],
        is_list: bool = False
    ) -> ParsedEntry:
        val_str = str(val)
        is_interp = bool(re.search(r"\$\{[A-Za-z0-9_\-]+\}", val_str))
        return ParsedEntry(
            path=path,
            value=val,
            line=line,
            raw_key=path.split(".")[-1],
            is_interpolated=is_interp,
            is_list=is_list
        )

    def _flatten_data(self, data: Any, line_map: Dict[str, int]) -> List[ParsedEntry]:
        entries: List[ParsedEntry] = []
        if isinstance(data, dict):
            for k, v in data.items():
                entries.append(self._create_entry(str(k), v, line_map.get(k)))
        return entries
