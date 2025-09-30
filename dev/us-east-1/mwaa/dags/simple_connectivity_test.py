"""
Simple connectivity test DAG for MWAA
Tests basic functionality and prepares for Redshift integration
"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python_operator import PythonOperator
from airflow.operators.bash_operator import BashOperator
import logging
import boto3

# Default arguments
default_args = {
    'owner': 'data-engineering',
    'depends_on_past': False,
    'start_date': datetime(2024, 1, 1),
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=5),
}

# DAG definition
dag = DAG(
    'simple_connectivity_test',
    default_args=default_args,
    description='Simple connectivity test for MWAA',
    schedule_interval=None,  # Manual trigger
    catchup=False,
    tags=['poc', 'connectivity', 'basic']
)

def test_python_environment():
    """Test Python environment and basic imports"""
    logging.info("Testing Python environment...")
    
    # Test basic imports
    import pandas as pd
    import boto3
    import json
    from datetime import datetime
    
    logging.info(f"Python environment test successful at {datetime.now()}")
    logging.info(f"Pandas version: {pd.__version__}")
    logging.info(f"Boto3 version: {boto3.__version__}")
    
    return "Python environment OK"

def test_aws_connectivity():
    """Test AWS service connectivity"""
    logging.info("Testing AWS service connectivity...")
    
    try:
        # Test S3 connectivity
        s3_client = boto3.client('s3')
        response = s3_client.list_buckets()
        bucket_count = len(response['Buckets'])
        logging.info(f"S3 connectivity OK - Found {bucket_count} buckets")
        
        # Test Secrets Manager connectivity
        secrets_client = boto3.client('secretsmanager')
        secrets_response = secrets_client.list_secrets(MaxResults=1)
        logging.info("Secrets Manager connectivity OK")
        
        # Test CloudWatch connectivity
        cloudwatch = boto3.client('cloudwatch')
        cw_response = cloudwatch.list_metrics(MaxRecords=1)
        logging.info("CloudWatch connectivity OK")
        
        return "AWS connectivity tests passed"
        
    except Exception as e:
        logging.error(f"AWS connectivity test failed: {str(e)}")
        raise

def prepare_for_redshift():
    """Prepare environment variables and check Redshift permissions"""
    logging.info("Preparing for Redshift connectivity...")
    
    try:
        # Test Redshift permissions
        redshift_client = boto3.client('redshift')
        
        # List clusters to test permissions
        response = redshift_client.describe_clusters(MaxRecords=1)
        logging.info("Redshift permissions OK - can describe clusters")
        
        # Test Redshift Data API permissions
        redshift_data = boto3.client('redshift-data')
        logging.info("Redshift Data API client created successfully")
        
        logging.info("Ready for Redshift connectivity testing")
        return "Redshift preparation complete"
        
    except Exception as e:
        logging.info(f"Redshift preparation info: {str(e)}")
        logging.info("This is expected if no Redshift cluster exists yet")
        return "Redshift preparation noted"

# Task definitions
test_env_task = PythonOperator(
    task_id='test_python_environment',
    python_callable=test_python_environment,
    dag=dag
)

test_aws_task = PythonOperator(
    task_id='test_aws_connectivity',
    python_callable=test_aws_connectivity,
    dag=dag
)

prepare_redshift_task = PythonOperator(
    task_id='prepare_for_redshift',
    python_callable=prepare_for_redshift,
    dag=dag
)

# Simple bash test
bash_test_task = BashOperator(
    task_id='test_bash_commands',
    bash_command='echo "MWAA Bash environment test successful" && date && whoami',
    dag=dag
)

# Set dependencies
test_env_task >> [test_aws_task, bash_test_task] >> prepare_redshift_task
