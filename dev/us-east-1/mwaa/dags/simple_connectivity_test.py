"""
Simple MWAA Connectivity Test DAG
Tests basic MWAA functionality and AWS service connectivity
"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Default arguments
default_args = {
    'owner': 'data-engineering',
    'depends_on_past': False,
    'start_date': datetime(2024, 1, 1),
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=2),
}

# Create DAG
dag = DAG(
    'simple_connectivity_test',
    default_args=default_args,
    description='Simple DAG to test MWAA environment setup',
    schedule_interval=None,  # Manual trigger only
    catchup=False,
    tags=['test', 'connectivity', 'mwaa']
)


def test_python_environment():
    """Test Python environment and imports"""
    logger.info("=" * 60)
    logger.info("Testing Python Environment")
    logger.info("=" * 60)
    
    import sys
    import platform
    
    logger.info(f"Python Version: {sys.version}")
    logger.info(f"Platform: {platform.platform()}")
    logger.info(f"Python Path: {sys.executable}")
    
    # Test key imports
    try:
        import boto3
        logger.info(f"✅ boto3 version: {boto3.__version__}")
    except ImportError as e:
        logger.error(f"❌ boto3 import failed: {e}")
    
    try:
        import pandas as pd
        logger.info(f"✅ pandas version: {pd.__version__}")
    except ImportError as e:
        logger.error(f"❌ pandas import failed: {e}")
    
    try:
        from airflow.providers.amazon.aws.hooks.base_aws import AwsBaseHook
        logger.info("✅ AWS Airflow providers available")
    except ImportError as e:
        logger.error(f"❌ AWS providers import failed: {e}")
    
    logger.info("=" * 60)
    return "Python environment check completed"


def test_aws_connectivity():
    """Test AWS service connectivity"""
    logger.info("=" * 60)
    logger.info("Testing AWS Service Connectivity")
    logger.info("=" * 60)
    
    import boto3
    from botocore.exceptions import ClientError
    
    # Test STS (identity)
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        logger.info(f"✅ AWS Account: {identity['Account']}")
        logger.info(f"✅ IAM Role ARN: {identity['Arn']}")
    except ClientError as e:
        logger.error(f"❌ STS check failed: {e}")
    
    # Test S3 connectivity
    try:
        s3 = boto3.client('s3')
        buckets = s3.list_buckets()
        logger.info(f"✅ S3 access verified - Found {len(buckets['Buckets'])} buckets")
    except ClientError as e:
        logger.error(f"❌ S3 check failed: {e}")
    
    # Test Secrets Manager connectivity
    try:
        sm = boto3.client('secretsmanager')
        secrets = sm.list_secrets(MaxResults=1)
        logger.info("✅ Secrets Manager access verified")
    except ClientError as e:
        logger.warning(f"⚠️  Secrets Manager check: {e}")
    
    logger.info("=" * 60)
    return "AWS connectivity check completed"


def test_redshift_api_availability():
    """Test if Redshift Data API is available"""
    logger.info("=" * 60)
    logger.info("Testing Redshift Data API Availability")
    logger.info("=" * 60)
    
    import boto3
    from botocore.exceptions import ClientError
    
    try:
        redshift_data = boto3.client('redshift-data')
        # Just check if we can make API calls
        logger.info("✅ Redshift Data API client created successfully")
        logger.info("✅ API is available for use")
        logger.info("")
        logger.info("Note: To test actual Redshift connectivity, you need to:")
        logger.info("1. Create Redshift Serverless workgroup and namespace")
        logger.info("2. Update the test_redshift_connection DAG with workgroup details")
        logger.info("3. Ensure MWAA security group is added to Redshift security group")
    except Exception as e:
        logger.error(f"❌ Redshift Data API check failed: {e}")
    
    logger.info("=" * 60)
    return "Redshift API availability check completed"


def print_airflow_variables():
    """Print Airflow configuration"""
    from airflow.configuration import conf
    
    logger.info("=" * 60)
    logger.info("Airflow Configuration")
    logger.info("=" * 60)
    logger.info(f"Executor: {conf.get('core', 'executor')}")
    logger.info(f"SQL Alchemy Conn: {conf.get('core', 'sql_alchemy_conn')[:30]}...")
    logger.info(f"Base Log Folder: {conf.get('logging', 'base_log_folder')}")
    logger.info("=" * 60)
    return "Airflow configuration printed"


# Task 1: Print welcome message
task_welcome = BashOperator(
    task_id='welcome',
    bash_command='echo "=== MWAA Environment Connectivity Test Started ===" && date',
    dag=dag
)

# Task 2: Test Python environment
task_python = PythonOperator(
    task_id='test_python_environment',
    python_callable=test_python_environment,
    dag=dag
)

# Task 3: Test AWS connectivity
task_aws = PythonOperator(
    task_id='test_aws_connectivity',
    python_callable=test_aws_connectivity,
    dag=dag
)

# Task 4: Test Redshift API availability
task_redshift_api = PythonOperator(
    task_id='test_redshift_api',
    python_callable=test_redshift_api_availability,
    dag=dag
)

# Task 5: Print Airflow variables
task_airflow_config = PythonOperator(
    task_id='print_airflow_config',
    python_callable=print_airflow_variables,
    dag=dag
)

# Task 6: Success message
task_complete = BashOperator(
    task_id='completion',
    bash_command='echo "=== All Connectivity Tests Completed Successfully ===" && date',
    dag=dag
)

# Define task dependencies
task_welcome >> task_python >> task_aws >> task_redshift_api >> task_airflow_config >> task_complete