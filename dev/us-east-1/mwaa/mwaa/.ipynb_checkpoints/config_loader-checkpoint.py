# mwaa/config_loader.py
import yaml
import os
from typing import Dict, Any, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ConfigLoaderError(Exception):
    """Custom exception for configuration loading errors"""
    pass

class ConfigLoader:
    """Load configuration from config/config.yaml and expose helper getters with validation."""

    def __init__(self, config_path: Optional[str] = None):
        # default path relative to repo root
        self.config_path = config_path or os.path.join(os.getcwd(), "config", "config.yaml")
        self._config: Optional[Dict[str, Any]] = None

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file with error handling"""
        if self._config is None:
            try:
                if not os.path.exists(self.config_path):
                    raise ConfigLoaderError(f"Config file not found at {self.config_path}")
                
                with open(self.config_path, "r", encoding='utf-8') as fh:
                    self._config = yaml.safe_load(fh)
                
                if not self._config:
                    raise ConfigLoaderError("Configuration file is empty or invalid")
                
                # Validate basic structure
                self._validate_config_structure(self._config)
                
                logger.info(f"Successfully loaded configuration from {self.config_path}")
                
            except yaml.YAMLError as e:
                raise ConfigLoaderError(f"Invalid YAML in config file: {str(e)}")
            except Exception as e:
                logger.error(f"Error loading configuration: {str(e)}")
                raise ConfigLoaderError(f"Failed to load configuration: {str(e)}")
                
        return self._config

    def _validate_config_structure(self, config: Dict[str, Any]) -> None:
        """Validate the basic structure of the configuration"""
        if 'environments' not in config:
            raise ConfigLoaderError("Configuration must contain 'environments' section")
        
        if not isinstance(config['environments'], dict):
            raise ConfigLoaderError("'environments' must be a dictionary")
        
        if not config['environments']:
            raise ConfigLoaderError("At least one environment must be defined")

    def get_environment_config(self, env_name: str = "dev") -> Dict[str, Any]:
        """Get environment configuration with validation"""
        try:
            cfg = self.load_config()
            envs = cfg.get("environments", {})
            
            if env_name not in envs:
                available_envs = list(envs.keys())
                raise ConfigLoaderError(f"Environment '{env_name}' not found. Available environments: {available_envs}")
            
            env_config = envs[env_name]
            
            # Validate environment configuration
            self._validate_environment_config(env_config, env_name)
            
            return env_config
            
        except ConfigLoaderError:
            raise
        except Exception as e:
            logger.error(f"Error getting environment config for '{env_name}': {str(e)}")
            raise ConfigLoaderError(f"Failed to get environment config: {str(e)}")

    def _validate_environment_config(self, env_config: Dict[str, Any], env_name: str) -> None:
        """Validate environment configuration"""
        required_sections = ['accounts', 'region', 'vpc', 'mwaa', 'tags']
        
        for section in required_sections:
            if section not in env_config:
                raise ConfigLoaderError(f"Environment '{env_name}' missing required section: '{section}'")
        
        # Validate VPC configuration
        vpc_config = env_config['vpc']
        required_vpc_fields = ['id', 'private_subnet_ids']
        for field in required_vpc_fields:
            if field not in vpc_config:
                raise ConfigLoaderError(f"Environment '{env_name}' VPC config missing: '{field}'")
        
        # Validate subnet IDs format
        subnet_ids = vpc_config['private_subnet_ids']
        if not isinstance(subnet_ids, list) or len(subnet_ids) < 2:
            raise ConfigLoaderError(f"Environment '{env_name}' must have at least 2 private subnet IDs")
        
        # Validate MWAA configuration
        mwaa_config = env_config['mwaa']
        required_mwaa_fields = [
            'name', 'dags_s3_bucket', 'dags_folder', 'airflow_version', 
            'environment_class', 'min_workers', 'max_workers', 
            'webserver_access_mode', 'logging'
        ]
        for field in required_mwaa_fields:
            if field not in mwaa_config:
                raise ConfigLoaderError(f"Environment '{env_name}' MWAA config missing: '{field}'")

    def get_account_id(self, env_name: str = "dev", account_name: str = "account1") -> str:
        """Get account ID with validation"""
        try:
            env = self.get_environment_config(env_name)
            accounts = env.get("accounts", {})
            
            if account_name not in accounts:
                available_accounts = list(accounts.keys())
                raise ConfigLoaderError(f"Account '{account_name}' not found in environment '{env_name}'. Available accounts: {available_accounts}")
            
            account_id = accounts[account_name]
            
            # Validate account ID format (12 digits)
            if not isinstance(account_id, str) or not account_id.isdigit() or len(account_id) != 12:
                raise ConfigLoaderError(f"Invalid account ID format for '{account_name}' in environment '{env_name}'. Must be 12 digits.")
            
            return account_id
            
        except ConfigLoaderError:
            raise
        except Exception as e:
            logger.error(f"Error getting account ID: {str(e)}")
            raise ConfigLoaderError(f"Failed to get account ID: {str(e)}")

    def get_vpc_config(self, env_name: str = "dev") -> Dict[str, Any]:
        """Get VPC configuration with validation"""
        try:
            env = self.get_environment_config(env_name)
            vpc_config = env.get("vpc", {})
            
            # Additional VPC validation
            vpc_id = vpc_config.get('id')
            if not vpc_id or not vpc_id.startswith('vpc-'):
                raise ConfigLoaderError(f"Invalid VPC ID format in environment '{env_name}'. Must start with 'vpc-'")
            
            subnet_ids = vpc_config.get('private_subnet_ids', [])
            for subnet_id in subnet_ids:
                if not subnet_id.startswith('subnet-'):
                    raise ConfigLoaderError(f"Invalid subnet ID format in environment '{env_name}': {subnet_id}. Must start with 'subnet-'")
            
            # Validate security group ID if provided
            sg_id = vpc_config.get('security_group_id')
            if sg_id and not sg_id.startswith('sg-'):
                raise ConfigLoaderError(f"Invalid security group ID format in environment '{env_name}': {sg_id}. Must start with 'sg-'")
            
            return vpc_config
            
        except ConfigLoaderError:
            raise
        except Exception as e:
            logger.error(f"Error getting VPC config: {str(e)}")
            raise ConfigLoaderError(f"Failed to get VPC config: {str(e)}")

    def get_mwaa_config(self, env_name: str = "dev") -> Dict[str, Any]:
        """Get MWAA configuration with validation"""
        try:
            env = self.get_environment_config(env_name)
            mwaa_config = env.get("mwaa", {})
            
            # Additional MWAA validation
            environment_class = mwaa_config.get('environment_class')
            valid_classes = ['mw1.micro', 'mw1.small', 'mw1.medium', 'mw1.large', 'mw1.xlarge', 'mw1.2xlarge']
            if environment_class not in valid_classes:
                raise ConfigLoaderError(f"Invalid environment class '{environment_class}' in environment '{env_name}'. Must be one of: {valid_classes}")
            
            # Validate worker configuration
            min_workers = mwaa_config.get('min_workers', 1)
            max_workers = mwaa_config.get('max_workers', 1)
            
            if not isinstance(min_workers, int) or min_workers < 1:
                raise ConfigLoaderError(f"min_workers must be an integer >= 1 in environment '{env_name}'")
            
            if not isinstance(max_workers, int) or max_workers < min_workers:
                raise ConfigLoaderError(f"max_workers must be an integer >= min_workers in environment '{env_name}'")
            
            # Validate webserver access mode
            access_mode = mwaa_config.get('webserver_access_mode')
            valid_modes = ['PRIVATE_ONLY', 'PUBLIC_ONLY']
            if access_mode not in valid_modes:
                raise ConfigLoaderError(f"Invalid webserver access mode '{access_mode}' in environment '{env_name}'. Must be one of: {valid_modes}")
            
            # Validate Airflow version
            airflow_version = mwaa_config.get('airflow_version')
            valid_versions = ['1.10.12', '2.0.2', '2.2.2', '2.4.3', '2.5.1', '2.6.3', '2.7.2', '2.8.1', '2.9.2', '2.10.1']
            if airflow_version not in valid_versions:
                raise ConfigLoaderError(f"Invalid Airflow version '{airflow_version}' in environment '{env_name}'. Must be one of: {valid_versions}")
            
            # Validate bucket name format
            bucket_name = mwaa_config.get('dags_s3_bucket')
            if not bucket_name or len(bucket_name) < 3 or len(bucket_name) > 63:
                raise ConfigLoaderError(f"Invalid S3 bucket name '{bucket_name}' in environment '{env_name}'. Must be 3-63 characters.")
            
            return mwaa_config
            
        except ConfigLoaderError:
            raise
        except Exception as e:
            logger.error(f"Error getting MWAA config: {str(e)}")
            raise ConfigLoaderError(f"Failed to get MWAA config: {str(e)}")

    def get_tags_config(self, env_name: str = "dev") -> Dict[str, Any]:
        """Get tags configuration"""
        try:
            env = self.get_environment_config(env_name)
            tags_config = env.get("tags", {})
            
            if not tags_config:
                logger.warning(f"No tags configuration found for environment '{env_name}'")
                return {}
            
            # Validate tags
            for key, value in tags_config.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise ConfigLoaderError(f"Invalid tag format in environment '{env_name}'. Keys and values must be strings.")
            
            return tags_config
            
        except ConfigLoaderError:
            raise
        except Exception as e:
            logger.error(f"Error getting tags config: {str(e)}")
            raise ConfigLoaderError(f"Failed to get tags config: {str(e)}")

    def get_region(self, env_name: str = "dev") -> str:
        """Get AWS region for environment"""
        try:
            env = self.get_environment_config(env_name)
            region = env.get("region")
            
            if not region:
                raise ConfigLoaderError(f"Region not specified for environment '{env_name}'")
            
            # Basic region format validation
            if not isinstance(region, str) or len(region) < 9:  # us-west-2 is 9 chars
                raise ConfigLoaderError(f"Invalid region format '{region}' for environment '{env_name}'")
            
            return region
            
        except ConfigLoaderError:
            raise
        except Exception as e:
            logger.error(f"Error getting region: {str(e)}")
            raise ConfigLoaderError(f"Failed to get region: {str(e)}")

    def validate_configuration(self, env_name: str = "dev") -> bool:
        """Validate complete configuration for an environment"""
        try:
            self.get_environment_config(env_name)
            self.get_account_id(env_name)
            self.get_vpc_config(env_name)
            self.get_mwaa_config(env_name)
            self.get_tags_config(env_name)
            self.get_region(env_name)
            
            logger.info(f"Configuration validation successful for environment '{env_name}'")
            return True
            
        except ConfigLoaderError as e:
            logger.error(f"Configuration validation failed for environment '{env_name}': {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during validation for environment '{env_name}': {str(e)}")
            return False