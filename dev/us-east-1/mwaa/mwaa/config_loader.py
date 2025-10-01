# mwaa/config_loader.py
import yaml
import os
from typing import Dict, Any, Optional


class ConfigLoader:
    """Load configuration from config/config.yaml and expose helper getters."""

    def __init__(self, config_path: str = None):
        # default path relative to repo root
        self.config_path = config_path or os.path.join(os.getcwd(), "config", "config.yaml")
        self._config = None

    def load_config(self) -> Dict[str, Any]:
        if self._config is None:
            if not os.path.exists(self.config_path):
                raise FileNotFoundError(f"Config file not found at {self.config_path}")
            with open(self.config_path, "r") as fh:
                self._config = yaml.safe_load(fh)
        return self._config

    def get_environment_config(self, env_name: str = "dev") -> Dict[str, Any]:
        cfg = self.load_config()
        envs = cfg.get("environments", {})
        if env_name not in envs:
            raise KeyError(f"Environment '{env_name}' missing in config file")
        return envs[env_name]

    def get_account_id(self, env_name: str, account_name: str = "account1") -> str:
        env = self.get_environment_config(env_name)
        accounts = env.get("accounts", {})
        if account_name not in accounts:
            raise KeyError(f"Account '{account_name}' not found in environment '{env_name}'")
        return accounts[account_name]

    def get_vpc_config(self, env_name: str = "dev") -> Dict[str, Any]:
        env = self.get_environment_config(env_name)
        return env.get("vpc", {})

    def get_mwaa_config(self, env_name: str = "dev") -> Dict[str, Any]:
        env = self.get_environment_config(env_name)
        return env.get("mwaa", {})
