"""Opt-in TUI Runner forced-reconfiguration protection.

TUI Runner is a local ratatui process orchestrator: after launch, every mutating
action it takes (killing processes bound to configured ports, scaffolding a new
project, spawning configured dev commands) is driven entirely through in-process
keyboard menu selections rather than separate argv-level subcommands. Guard's
command hook only observes the shell command an agent adapter passes to it before
execution, so those interactive actions are not visible here and are out of scope
for this extension. The one argv-level flag that changes behavior without further
interactive confirmation is --reconfigure, which forces the setup wizard to run and
unconditionally overwrites any existing tui.config.json for the chosen project once
the wizard completes.
"""

from __future__ import annotations

from .command_extension_matchers import executable_names
from .command_extension_specs import CommandExtensionSpec
from .command_rules import CommandSafetyRule, ExecutableMatcher

_TUI_RUNNER_RECONFIGURE = ExecutableMatcher(
    executables=executable_names("tui-runner"),
    required_flags=frozenset({"--reconfigure"}),
    required_flags_in_all_arguments=True,
)

TUI_RUNNER_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.tui-runner.reconfigure",
        example_command="tui-runner --reconfigure",
        title="TUI Runner forced reconfiguration",
        description=(
            "Identifies TUI Runner invocations with --reconfigure, which forces the setup wizard to "
            "run and unconditionally overwrites any existing tui.config.json for the chosen project "
            "once the wizard completes."
        ),
        matcher=_TUI_RUNNER_RECONFIGURE,
        action_classes=("tui-runner forced reconfiguration command",),
        safer_alternatives=(
            "Inspect the project's existing tui.config.json before forcing --reconfigure, since the "
            "wizard replaces it without a separate confirmation step.",
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        compatibility_fallback=True,
    ),
)

TUI_RUNNER_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.tui-runner",
        name="TUI Runner forced reconfiguration protection",
        description=(
            "Reviews TUI Runner --reconfigure invocations, which overwrite a project's saved process "
            "configuration. Port cleanup, process spawning, and project scaffolding happen through "
            "TUI Runner's interactive menu after launch and are not observable command-line events, "
            "so this extension does not cover them."
        ),
        action_classes=("tui-runner forced reconfiguration command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=("Review the saved tui.config.json before forcing a reconfiguration that will replace it.",),
        reference_urls=(),
    ),
)
