"""Configuration loader for adapter configs.

Loads adapter definitions from YAML files, allowing the broker
to know which systems are available and how to reach them.

Example adapters.yaml:
```yaml
adapters:
  - system_name: crm
    adapter_type: http
    config:
      base_url: "https://api.salesforce.com/v2"
      timeout_seconds: 30
      actions:
        read_account:
          method: GET
          path: "/accounts/${account_id}"
        update_contact:
          method: PATCH
          path: "/contacts/${contact_id}"
          body_template:
            field: "${field}"
            value: "${value}"
    credentials:
      type: bearer
      token: "${JITAUTH_CRM_TOKEN}"

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
```
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import yaml

from jitauth.proxy.base import AdapterConfig
from jitauth.proxy.gateway import register_adapter_config

logger = logging.getLogger(__name__)


def load_adapter_configs(config_path: str | Path) -> list[AdapterConfig]:
    """Load adapter configurations from a YAML file.

    Environment variables in credential values are resolved
    (e.g., ${JITAUTH_CRM_TOKEN} → os.environ["JITAUTH_CRM_TOKEN"]).
    """
    path = Path(config_path)
    if not path.exists():
        logger.warning("Adapter config file not found: %s", path)
        return []

    with open(path) as f:
        doc = yaml.safe_load(f)

    if not doc or "adapters" not in doc:
        logger.warning("No adapters defined in %s", path)
        return []

    configs = []
    for adapter_def in doc["adapters"]:
        # Resolve env vars in credentials
        credentials = adapter_def.get("credentials", {})
        resolved_creds = _resolve_env_vars(credentials)

        config = AdapterConfig(
            system_name=adapter_def["system_name"],
            adapter_type=adapter_def["adapter_type"],
            config=adapter_def.get("config", {}),
            credentials=resolved_creds,
        )
        configs.append(config)
        register_adapter_config(config)
        logger.info(
            "Loaded adapter config: %s (%s)",
            config.system_name,
            config.adapter_type,
        )

    return configs


def _resolve_env_vars(data: dict | str | list) -> dict | str | list:
    """Recursively resolve ${ENV_VAR} patterns in config values."""
    if isinstance(data, str):
        if data.startswith("${") and data.endswith("}"):
            var_name = data[2:-1]
            value = os.environ.get(var_name)
            if value is None:
                logger.warning("Environment variable %s not set", var_name)
                return data
            return value
        return data
    elif isinstance(data, dict):
        return {k: _resolve_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_resolve_env_vars(item) for item in data]
    return data
