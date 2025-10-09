#!/usr/bin/env python3
import os
import sys
import yaml
from aws_cdk import App, Environment, Tags
from mwaa.mwaa_stack import MWAAStack

def load_config():
    """Load configuration from config.yaml"""
    try:
        import yaml
    except ImportError:
        print("Error: PyYAML is required. Install with: pip install PyYAML")
        sys.exit(1)
    
    try:
        config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.yaml')
        if not os.path.exists(config_path):
            print(f"Error: Configuration file not found at {config_path}")
            sys.exit(1)
            
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
            
        if not config:
            print("Error: Configuration file is empty")
            sys.exit(1)
            
        return config
        
    except FileNotFoundError:
        print("Error: config/config.yaml not found")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing config.yaml: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error loading config: {e}")
        sys.exit(1)

def validate_config(config, env_name):
    """Validate configuration structure"""
    if 'environments' not in config:
        raise ValueError("Configuration must contain 'environments' section")
    
    if env_name not in config['environments']:
        available_envs = list(config['environments'].keys())
        raise ValueError(f"Environment '{env_name}' not found. Available: {available_envs}")
    
    env_config = config['environments'][env_name]
    
    # Validate required sections
    required_sections = ['accounts', 'region', 'vpc', 'mwaa']
    for section in required_sections:
        if section not in env_config:
            raise ValueError(f"Missing required section '{section}' in environment '{env_name}'")
    
    # Validate accounts
    if not env_config['accounts'] or not isinstance(env_config['accounts'], dict):
        raise ValueError(f"Environment '{env_name}' must have at least one account")
    
    return env_config

def main():
    """Main CDK app entry point"""
    try:
        app = App()
        
        # Load configuration
        config = load_config()
        
        # Get environment from context or default to 'dev'
        env_name = app.node.try_get_context("environment") or "dev"
        print(f"Deploying environment: {env_name}")
        
        # Validate configuration
        env_config = validate_config(config, env_name)
        
        # Iterate through accounts for the environment
        for account_name, account_id in env_config['accounts'].items():
            print(f"Creating stack for account: {account_name} ({account_id})")
            
            stack_name = f"mwaa-cdk-{env_name}-{account_name}"
            
            # Validate account ID format
            if not account_id or not isinstance(account_id, str) or len(account_id) != 12:
                raise ValueError(f"Invalid account ID for {account_name}: {account_id}")
            
            # Create environment object
            cdk_env = Environment(
                account=account_id,
                region=env_config['region']
            )
            
            # Create MWAA stack
            mwaa_stack = MWAAStack(
                app,
                stack_name,
                env_config=env_config,
                env_name=env_name,
                account_name=account_name,
                env=cdk_env,
                description=f"MWAA Environment Stack for {env_name}-{account_name}"
            )
            
            # Apply tags
            if 'tags' in env_config:
                for key, value in env_config['tags'].items():
                    Tags.of(mwaa_stack).add(key, value)
            
            # Add environment and account specific tags
            Tags.of(mwaa_stack).add("Environment", env_name)
            # Tags.of(mwaa_stack).add("Account", account_name)
            Tags.of(mwaa_stack).add("StackName", stack_name)
            Tags.of(mwaa_stack).add("ManagedBy", "AWS-CDK")
        
        print("Synthesizing CDK app...")
        app.synth()
        print("CDK synthesis completed successfully!")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()