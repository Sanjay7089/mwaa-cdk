import yaml
import os
from typing import Dict, Any

class ConfigLoader:
    """Load configuration from YAML file"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config_path = config_path
        self._config = None
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if self._config is None:
            with open(self.config_path, 'r') as file:
                self._config = yaml.safe_load(file)
        return self._config
    
    def get_environment_config(self, env_name: str) -> Dict[str, Any]:
        """Get configuration for a specific environment"""
        config = self.load_config()
        if env_name not in config.get('environments', {}):
            raise ValueError(f"Environment '{env_name}' not found in configuration")
        return config['environments'][env_name]
    
    def get_account_id(self, env_name: str, account_name: str) -> str:
        """Get account ID for environment and account"""
        env_config = self.get_environment_config(env_name)
        accounts = env_config.get('accounts', {})
        if account_name not in accounts:
            raise ValueError(f"Account '{account_name}' not found in environment '{env_name}'")
        return accounts[account_name]
    
    def get_vpc_config(self, env_name: str) -> Dict[str, Any]:
        """Get VPC configuration for environment"""
        env_config = self.get_environment_config(env_name)
        return env_config.get('vpc', {})
    
    def get_mwaa_config(self, env_name: str) -> Dict[str, Any]:
        """Get MWAA configuration for environment"""
        env_config = self.get_environment_config(env_name)
        return env_config.get('mwaa', {})
