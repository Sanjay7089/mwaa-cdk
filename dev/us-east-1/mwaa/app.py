#!/usr/bin/env python3
import os
import aws_cdk as cdk
from mwaa.mwaa_stack import MwaaStack
from mwaa.config_loader import ConfigLoader

# Initialize CDK app
app = cdk.App()

# Load configuration
config_loader = ConfigLoader()

# Get environment name from context or default to 'dev'
env_name = app.node.try_get_context("environment") or "dev"
account_name = app.node.try_get_context("account") or "account1"

print("=" * 80)
print("MWAA CDK Deployment Configuration")
print("=" * 80)

# Load environment configuration
try:
    env_config = config_loader.get_environment_config(env_name)
    account_id = config_loader.get_account_id(env_name, account_name)
    vpc_config = config_loader.get_vpc_config(env_name)
    mwaa_config = config_loader.get_mwaa_config(env_name)
    region = env_config["region"]
    
    print(f"Environment:           {env_name}")
    print(f"AWS Account:           {account_id}")
    print(f"Region:                {region}")
    print(f"MWAA Environment:      {mwaa_config['name']}")
    print(f"VPC ID:                {vpc_config['id']}")
    print(f"Private Subnets:       {', '.join(vpc_config['private_subnet_ids'])}")
    print(f"S3 Bucket:             {mwaa_config['dags_s3_bucket']}")
    print(f"Airflow Version:       {mwaa_config['airflow_version']}")
    print(f"Environment Class:     {mwaa_config['environment_class']}")
    print(f"Workers:               {mwaa_config['min_workers']}-{mwaa_config['max_workers']}")
    print(f"Web Access Mode:       {mwaa_config['webserver_access_mode']}")
    print("=" * 80)
    
except Exception as e:
    print(f"❌ ERROR: Failed to load configuration")
    print(f"Details: {e}")
    print("\nPlease check your config/config.yaml file")
    exit(1)

# Create MWAA stack
try:
    mwaa_stack = MwaaStack(
        app,
        f"{mwaa_config['name']}-stack",
        mwaa_config=mwaa_config,
        vpc_config=vpc_config,
        env=cdk.Environment(
            account=account_id,
            region=region
        ),
        description=f"MWAA Environment Stack for {mwaa_config['name']}"
    )
    
    # Add tags to all resources
    cdk.Tags.of(app).add("Project", "MWAA-Redshift-Integration")
    cdk.Tags.of(app).add("Environment", env_name)
    cdk.Tags.of(app).add("ManagedBy", "AWS-CDK")
    cdk.Tags.of(app).add("Owner", "DataEngineering")
    
    print("✅ Stack configuration successful")
    print(f"Stack Name: {mwaa_stack.stack_name}")
    print("=" * 80)
    
except Exception as e:
    print(f"❌ ERROR: Failed to create stack")
    print(f"Details: {e}")
    exit(1)

# Synthesize CloudFormation template
app.synth()