#!/usr/bin/env python3
import os
import aws_cdk as cdk
from mwaa.mwaa_stack import MwaaStack
from mwaa.airflow_source_stack import AirflowSourceStack
from mwaa.config_loader import ConfigLoader

# Initialize CDK app
app = cdk.App()

# Load configuration
config_loader = ConfigLoader()

# Get environment name from context or default to 'dev'
env_name = app.node.try_get_context("environment") or "dev"
account_name = app.node.try_get_context("account") or "account1"

# Load environment configuration
try:
    env_config = config_loader.get_environment_config(env_name)
    account_id = config_loader.get_account_id(env_name, account_name)
    vpc_config = config_loader.get_vpc_config(env_name)
    mwaa_config = config_loader.get_mwaa_config(env_name)
    region = env_config["region"]
    
    print(f"Deploying to environment: {env_name}")
    print(f"Account: {account_id}")
    print(f"Region: {region}")
    print(f"MWAA Environment: {mwaa_config['name']}")
    
except Exception as e:
    print(f"Error loading configuration: {e}")
    exit(1)

# Create S3 bucket for MWAA source code
mwaa_source = AirflowSourceStack(
    app, 
    f"{mwaa_config['name']}-source-stack",
    bucket_name=mwaa_config["dags_s3_bucket"],
    env=cdk.Environment(account=account_id, region=region)
)

# Create MWAA stack
mwaa_stack = MwaaStack(
    app,
    f"{mwaa_config['name']}-stack",
    source_bucket=mwaa_source.source_bucket,
    mwaa_config=mwaa_config,
    vpc_config=vpc_config,
    env=cdk.Environment(account=account_id, region=region)
)

# Add dependency
mwaa_stack.add_dependency(mwaa_source)

# Add tags
cdk.Tags.of(app).add("Project", "MWAA-POC")
cdk.Tags.of(app).add("Environment", env_name)
cdk.Tags.of(app).add("ManagedBy", "CDK")

app.synth()
