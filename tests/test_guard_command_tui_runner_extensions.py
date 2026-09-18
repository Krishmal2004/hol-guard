"""TUI Runner forced-reconfiguration command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.extension_builder.listing import category_for_extension
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from tests.command_extension_contracts import assert_safe_command_cases

TUI_RUNNER_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("tui-runner --reconfigure", "tui-runner forced reconfiguration command", "command.tui-runner.reconfigure"),
    (
        "tui-runner.exe --reconfigure",
        "tui-runner forced reconfiguration command",
        "command.tui-runner.reconfigure",
    ),
    (
        "tui-runner.cmd --reconfigure",
        "tui-runner forced reconfiguration command",
        "command.tui-runner.reconfigure",
    ),
    (
        "./target/release/tui-runner --reconfigure",
        "tui-runner forced reconfiguration command",
        "command.tui-runner.reconfigure",
    ),
)


def _tui_runner_control_layer(state: ControlState) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, "command.tui-runner"),
                state=state,
            ),
        ),
    )


def test_tui_runner_rules_are_inert_until_local_admin_enable(tmp_path: Path) -> None:
    for command, action_class, rule_id in TUI_RUNNER_REVIEW_CASES:
        inert = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            compatibility_action_class=action_class,
            extension_control_layers=(),
        )
        assert all(item.extension.extension_id != "command.tui-runner" for item in inert.extension_observations)
        assert all(item.extension.extension_id != "command.tui-runner" for item in inert.matches)
        assert inert.controlling_action_class is None
        assert inert.controlling_rule_id is None

        enabled = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            compatibility_action_class=action_class,
            extension_control_layers=(_tui_runner_control_layer(ControlState.ENABLED),),
        )
        assert any(item.extension.extension_id == "command.tui-runner" for item in enabled.extension_observations)
        assert any(item.extension.extension_id == "command.tui-runner" for item in enabled.matches)
        assert enabled.controlling_action_class == action_class
        assert enabled.controlling_rule_id == rule_id

        disabled = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            compatibility_action_class=action_class,
            extension_control_layers=(_tui_runner_control_layer(ControlState.DISABLED),),
        )
        assert all(item.extension.extension_id != "command.tui-runner" for item in disabled.extension_observations)
        assert all(item.extension.extension_id != "command.tui-runner" for item in disabled.matches)
        assert disabled.controlling_action_class is None
        assert disabled.controlling_rule_id is None


TUI_RUNNER_SAFE_COMMANDS: tuple[str, ...] = (
    "tui-runner",
    "tui-runner.exe",
    "tui-runner --help",
    "tui-runner --reconfigur",
    "tui-runner reconfigure",
    "echo tui-runner --reconfigure",
    "grep 'tui-runner --reconfigure' docs",
)


def test_tui_runner_launch_and_preview_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(TUI_RUNNER_SAFE_COMMANDS, tmp_path)


def test_tui_runner_action_publishes_risk_classes() -> None:
    assert risk_classes_for_command_action("tui-runner forced reconfiguration command") == ("destructive_shell",)


def test_tui_runner_extension_documents_interactive_coverage_limit() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.tui-runner")

    assert extension is not None
    assert extension.required is False
    description = extension.description.lower()
    assert "interactive" in description
    assert "port cleanup" in description
    assert "scaffolding" in description


def test_tui_runner_extension_is_categorized() -> None:
    assert category_for_extension("command.tui-runner") == "specialized-tools"
