"""Shell command adapter — allowlisted command templates only.

This adapter does NOT give agents shell access. It executes
pre-defined command templates with validated parameters.

Every command must be explicitly allowlisted in the adapter config.
No raw shell input from the runtime is ever executed.

Config schema:
```yaml
adapters:
  - system_name: devtools
    adapter_type: shell
    config:
      working_dir: /opt/app
      timeout_seconds: 30
      commands:
        git_log:
          template: "git log --oneline -n ${count}"
          params:
            count:
              type: int
              min: 1
              max: 100
              default: 10
        list_files:
          template: "ls -la ${path}"
          params:
            path:
              type: string
              pattern: "^[a-zA-Z0-9_./-]+$"
              max_length: 200
```
"""

from __future__ import annotations

import asyncio
import logging
import re
import shlex
from string import Template
from typing import Any

from jitauth.proxy.base import AdapterConfig, AdapterResult, BaseAdapter

logger = logging.getLogger(__name__)

# Characters that should never appear in shell parameters
_DANGEROUS_CHARS = set(";|&`$(){}[]!#~")

# Max output size
_MAX_OUTPUT_SIZE = 32 * 1024  # 32KB


class ShellAdapter(BaseAdapter):
    """Adapter for executing allowlisted shell commands."""

    def __init__(self, config: AdapterConfig):
        super().__init__(config)
        self.working_dir = config.config.get("working_dir")
        self.timeout = config.config.get("timeout_seconds", 30)
        self.commands_config = config.config.get("commands", {})
        self.supported_actions = list(self.commands_config.keys())

    async def execute(
        self,
        action: str,
        arguments: dict[str, Any],
        credential: dict[str, Any] | None = None,
    ) -> AdapterResult:
        if action not in self.commands_config:
            return AdapterResult(
                success=False,
                error=f"Command '{action}' is not in the allowlist for '{self.system_name}'",
            )

        cmd_def = self.commands_config[action]
        template = cmd_def.get("template", "")
        param_specs = cmd_def.get("params", {})

        # Validate all parameters
        validated_params = {}
        for param_name, spec in param_specs.items():
            value = arguments.get(param_name, spec.get("default"))
            if value is None:
                return AdapterResult(
                    success=False,
                    error=f"Missing required parameter '{param_name}' for command '{action}'",
                )

            validation_error = _validate_param(param_name, value, spec)
            if validation_error:
                return AdapterResult(success=False, error=validation_error)

            # Shell-escape the validated value
            validated_params[param_name] = shlex.quote(str(value))

        # Check for any arguments not in the spec (reject unexpected input)
        unexpected = set(arguments.keys()) - set(param_specs.keys())
        if unexpected:
            return AdapterResult(
                success=False,
                error=(
                    f"Unexpected parameters: {unexpected}. "
                    f"Only {set(param_specs.keys())} are allowed."
                ),
            )

        # Build the command
        try:
            command = Template(template).safe_substitute(validated_params)
        except Exception as e:
            return AdapterResult(success=False, error=f"Command template error: {e}")

        # Final safety check — no dangerous characters in the resolved command
        # that weren't in the original template
        template_chars = set(template)
        resolved_chars = set(command) - template_chars
        dangerous_found = resolved_chars & _DANGEROUS_CHARS
        if dangerous_found:
            logger.warning(
                "Blocked shell command with dangerous characters: %s (chars: %s)",
                action,
                dangerous_found,
            )
            return AdapterResult(
                success=False,
                error="Command rejected: parameters contain dangerous shell characters",
            )

        # Execute
        logger.info("Executing shell command [%s]: %s", action, command)
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.working_dir,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout
            )

            stdout_str = stdout.decode("utf-8", errors="replace")[:_MAX_OUTPUT_SIZE]
            stderr_str = stderr.decode("utf-8", errors="replace")[:_MAX_OUTPUT_SIZE]

            success = process.returncode == 0
            return AdapterResult(
                success=success,
                result={
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                    "return_code": process.returncode,
                }
                if success
                else None,
                error=f"Command failed (exit {process.returncode}): {stderr_str}"
                if not success
                else None,
            )

        except asyncio.TimeoutError:
            return AdapterResult(
                success=False, error=f"Command timed out after {self.timeout}s"
            )
        except Exception as e:
            logger.error("Shell adapter error for %s/%s: %s", self.system_name, action, e)
            return AdapterResult(success=False, error=f"Execution error: {type(e).__name__}: {e}")


def _validate_param(name: str, value: Any, spec: dict) -> str | None:
    """Validate a parameter value against its spec. Returns error string or None."""
    param_type = spec.get("type", "string")

    if param_type == "int":
        try:
            int_val = int(value)
        except (TypeError, ValueError):
            return f"Parameter '{name}' must be an integer, got '{value}'"
        if "min" in spec and int_val < spec["min"]:
            return f"Parameter '{name}' must be >= {spec['min']}, got {int_val}"
        if "max" in spec and int_val > spec["max"]:
            return f"Parameter '{name}' must be <= {spec['max']}, got {int_val}"

    elif param_type == "string":
        str_val = str(value)
        if "max_length" in spec and len(str_val) > spec["max_length"]:
            return f"Parameter '{name}' exceeds max length {spec['max_length']}"
        if "pattern" in spec and not re.match(spec["pattern"], str_val):
            return f"Parameter '{name}' does not match required pattern"
        # Always check for dangerous characters in string params
        dangerous = set(str_val) & _DANGEROUS_CHARS
        if dangerous:
            return f"Parameter '{name}' contains dangerous characters: {dangerous}"

    elif param_type == "enum":
        allowed = spec.get("values", [])
        if str(value) not in allowed:
            return f"Parameter '{name}' must be one of {allowed}, got '{value}'"

    return None
