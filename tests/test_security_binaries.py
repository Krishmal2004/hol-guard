"""Packaged Mach-O handling: recognition is bounded, and skipped binaries are reported, never passed."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from codex_plugin_scanner.checks import security
from codex_plugin_scanner.checks.security import (
    MAX_SCAN_FILE_BYTES,
    MAX_UNINSPECTED_BINARIES,
    ScanBudgetExceededError,
    _scan_all_files,
    check_no_hardcoded_secrets,
    run_security_checks,
)
from codex_plugin_scanner.checks.security_binaries import inspect_packaged_binary

OVER_LIMIT = MAX_SCAN_FILE_BYTES + 1024
SECRET_LINE = 'const token = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";\n'
MAGICS = {
    (False, True): b"\xcf\xfa\xed\xfe",
    (False, False): b"\xce\xfa\xed\xfe",
    (True, True): b"\xfe\xed\xfa\xcf",
    (True, False): b"\xfe\xed\xfa\xce",
}


def _thin(total: int, *, signed: bool = True, big_endian: bool = False, wide: bool = True) -> bytes:
    """A structurally valid Mach-O of ``total`` bytes whose single segment spans the file."""
    order = ">" if big_endian else "<"
    if wide:
        commands = struct.pack(f"{order}2I16s4Q4I", 0x19, 72, b"__TEXT", 0, total, 0, total, 5, 5, 0, 0)
    else:
        commands = struct.pack(f"{order}2I16s8I", 0x1, 56, b"__TEXT", 0, total, 0, total, 5, 5, 0, 0)
    count = 1
    if signed:
        commands += struct.pack(f"{order}4I", 0x1D, 16, total - 64, 64)
        count += 1
    header = MAGICS[(big_endian, wide)] + struct.pack(f"{order}6I", 0x0100000C, 0, 2, count, len(commands), 0)
    if wide:
        header += b"\x00" * 4
    body = header + commands
    return body + b"\x00" * (total - len(body))


def _fat(slices: list[bytes], *, wide: bool = False) -> bytes:
    entry_size = 32 if wide else 20
    head_size = 8 + entry_size * len(slices)
    offsets = []
    cursor = head_size
    for data in slices:
        cursor = (cursor + 0xFFF) & ~0xFFF
        offsets.append(cursor)
        cursor += len(data)
    out = bytearray((b"\xca\xfe\xba\xbf" if wide else b"\xca\xfe\xba\xbe") + struct.pack(">I", len(slices)))
    for offset, data in zip(offsets, slices, strict=True):
        if wide:
            out += struct.pack(">2I2Q2I", 0x0100000C, 0, offset, len(data), 12, 0)
        else:
            out += struct.pack(">5I", 0x0100000C, 0, offset, len(data), 12)
    for offset, data in zip(offsets, slices, strict=True):
        out += b"\x00" * (offset - len(out))
        out += data
    return bytes(out)


def _write_binary(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _plugin(tmp_path: Path) -> Path:
    root = tmp_path / "plugin"
    root.mkdir()
    return root


class TestRecognition:
    @pytest.mark.parametrize("big_endian", [False, True])
    @pytest.mark.parametrize("wide", [False, True])
    def test_recognizes_thin_variants(self, tmp_path: Path, big_endian: bool, wide: bool):
        path = _write_binary(tmp_path / "tool", _thin(8192, big_endian=big_endian, wide=wide))
        binary = inspect_packaged_binary(path)
        assert binary is not None
        assert binary.format == "mach-o"
        assert binary.code_signature_present is True

    def test_signature_is_context_only(self, tmp_path: Path):
        binary = inspect_packaged_binary(_write_binary(tmp_path / "tool", _thin(8192, signed=False)))
        assert binary is not None
        assert binary.code_signature_present is False

    @pytest.mark.parametrize("wide", [False, True])
    def test_recognizes_universal(self, tmp_path: Path, wide: bool):
        path = _write_binary(tmp_path / "tool", _fat([_thin(8192), _thin(12288)], wide=wide))
        binary = inspect_packaged_binary(path)
        assert binary is not None
        assert binary.format == "mach-o-universal"
        assert binary.architectures == 2

    def test_rejects_truncated_and_malformed(self, tmp_path: Path):
        good = _thin(8192)
        cases = {
            "empty": b"",
            "magic-only": good[:4],
            "short-header": good[:20],
            "truncated-commands": good[:60],
            "trailing-payload": good + b"#!/bin/sh\necho hi\n",
            "zero-commands": good[:16] + struct.pack("<2I", 0, 0) + good[24:],
            "text": b"console.log(1)\n" * 100,
            "java-class": b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 64,
            "fat-no-slices": b"\xca\xfe\xba\xbe\x00\x00\x00\x01" + b"\x00" * 12,
        }
        for name, data in cases.items():
            assert inspect_packaged_binary(_write_binary(tmp_path / name, data)) is None, name

    def test_rejects_fat_with_unrecognized_or_trailing_slice(self, tmp_path: Path):
        mixed = _fat([_thin(8192), b"MZ" + b"\x00" * 4094])
        assert inspect_packaged_binary(_write_binary(tmp_path / "a", mixed)) is None
        trailing = _fat([_thin(8192)]) + b"extra"
        assert inspect_packaged_binary(_write_binary(tmp_path / "b", trailing)) is None

    def test_symlink_is_not_followed(self, tmp_path: Path):
        target = _write_binary(tmp_path / "real", _thin(8192))
        link = tmp_path / "link"
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError):
            pytest.skip("symlinks are not supported in this environment")
        assert inspect_packaged_binary(link) is None


class TestScanning:
    def test_extensionless_binary_over_limit_is_skipped_and_reported(self, tmp_path: Path):
        root = _plugin(tmp_path)
        _write_binary(root / "binary" / "tool-darwin-arm64", _thin(OVER_LIMIT))
        (root / "src.js").write_text("console.log(1)\n", encoding="utf-8")
        skipped: list = []
        files = _scan_all_files(root.resolve(), None, skipped)
        assert [path.name for path in files] == ["src.js"]
        assert [item.path.name for item in skipped] == ["tool-darwin-arm64"]

    def test_universal_binary_over_limit_is_skipped(self, tmp_path: Path):
        root = _plugin(tmp_path)
        _write_binary(root / "tool", _fat([_thin(OVER_LIMIT // 2 + 1024), _thin(OVER_LIMIT // 2 + 1024)]))
        skipped: list = []
        assert _scan_all_files(root.resolve(), None, skipped) == []
        assert skipped[0].binary.format == "mach-o-universal"

    def test_default_walk_still_fails_closed_for_binaries(self, tmp_path: Path):
        root = _plugin(tmp_path)
        _write_binary(root / "tool", _thin(OVER_LIMIT))
        with pytest.raises(ScanBudgetExceededError):
            _scan_all_files(root.resolve())

    def test_oversized_text_without_extension_fails_closed(self, tmp_path: Path):
        root = _plugin(tmp_path)
        (root / "payload").write_bytes(SECRET_LINE.encode() * (OVER_LIMIT // len(SECRET_LINE) + 1))
        result = check_no_hardcoded_secrets(root)
        assert result.passed is False
        assert result.findings[0].rule_id == "SCAN_RESOURCE_BUDGET_EXCEEDED"

    def test_binary_header_before_payload_is_not_trusted(self, tmp_path: Path):
        root = _plugin(tmp_path)
        (root / "payload").write_bytes(_thin(8192) + SECRET_LINE.encode() * (OVER_LIMIT // len(SECRET_LINE) + 1))
        result = check_no_hardcoded_secrets(root)
        assert result.findings[0].rule_id == "SCAN_RESOURCE_BUDGET_EXCEEDED"

    def test_renamed_oversized_text_is_not_skipped(self, tmp_path: Path):
        root = _plugin(tmp_path)
        (root / "tool-darwin-arm64").write_bytes(b"a" * OVER_LIMIT)
        assert check_no_hardcoded_secrets(root).passed is False

    def test_source_findings_stay_visible_beside_a_binary(self, tmp_path: Path):
        root = _plugin(tmp_path)
        _write_binary(root / "binary" / "tool", _thin(OVER_LIMIT))
        (root / "src").mkdir()
        (root / "src" / "index.js").write_text(SECRET_LINE, encoding="utf-8")
        result = check_no_hardcoded_secrets(root)
        assert result.passed is False
        assert result.findings[0].file_path == "src/index.js"

    def test_skipped_binary_is_reported_not_passed(self, tmp_path: Path):
        root = _plugin(tmp_path)
        _write_binary(root / "binary" / "tool", _thin(OVER_LIMIT))
        results = {check.name: check for check in run_security_checks(root)}
        report = results["Packaged binaries not inspected"]
        assert report.passed is False
        assert report.max_points == 0
        finding = report.findings[0]
        assert finding.rule_id == "UNINSPECTED_PACKAGED_BINARY"
        assert finding.file_path == "binary/tool"
        assert "not scanned" in finding.description
        assert "excluding 1 uninspected" in results["No hardcoded secrets"].message

    def test_no_report_without_binaries(self, tmp_path: Path):
        root = _plugin(tmp_path)
        (root / "a.js").write_text("1\n", encoding="utf-8")
        assert "Packaged binaries not inspected" not in {c.name for c in run_security_checks(root)}

    def test_binary_count_is_bounded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        root = _plugin(tmp_path)
        monkeypatch.setattr(security, "MAX_UNINSPECTED_BINARIES", 1)
        for name in ("one", "two"):
            _write_binary(root / name, _thin(OVER_LIMIT))
        with pytest.raises(ScanBudgetExceededError):
            _scan_all_files(root.resolve(), None, [])
        assert MAX_UNINSPECTED_BINARIES == 64

    def test_symlinked_binary_is_ignored(self, tmp_path: Path):
        root = _plugin(tmp_path)
        outside = _write_binary(tmp_path / "outside-tool", _thin(OVER_LIMIT))
        try:
            (root / "tool").symlink_to(outside)
        except (NotImplementedError, OSError):
            pytest.skip("symlinks are not supported in this environment")
        skipped: list = []
        assert _scan_all_files(root.resolve(), None, skipped) == []
        assert skipped == []


def test_published_action_scan_path_reports_skipped_binary(tmp_path: Path):
    """The Action runs scan_plugin through the CLI; the scored result must carry the uninspected binary."""
    from codex_plugin_scanner.scanner import scan_plugin

    root = _plugin(tmp_path)
    (root / ".codex-plugin").mkdir()
    (root / ".codex-plugin" / "plugin.json").write_text(
        json.dumps({"name": "demo", "version": "1.0.0", "description": "Demo plugin"}), encoding="utf-8"
    )
    _write_binary(root / "binary" / "tool-darwin-arm64", _thin(OVER_LIMIT))
    (root / "index.js").write_text(SECRET_LINE, encoding="utf-8")
    result = scan_plugin(root)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "UNINSPECTED_PACKAGED_BINARY" in rule_ids
    assert "HARDCODED_SECRET" in rule_ids
    assert "SCAN_RESOURCE_BUDGET_EXCEEDED" not in rule_ids
