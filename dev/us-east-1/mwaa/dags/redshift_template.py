"""
Template DAG for Redshift connectivity testing
Update the connection details when Redshift cluster is ready
"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python_operator import PythonOperator
from airflow.providers.amazon.aws.operators.redshift_data import RedshiftDataOperator
from airflow.providers.amazon.aws.hooks.redshift_data import RedshiftDataHook
import logging

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

# DAG definition - DISABLED until Redshift is provisioned
dag = DAG(
    'redshift_connectivity_template',
    default_args=default_args,
    description='Template for Redshift connectivity (update cluster details)',
    schedule_interval=None,
    catchup=False,
    tags=['redshift', 'template', 'disabled'],
    is_paused_upon_creation=True  # Start as paused
)

def test_redshift_data_api():
    """Test Redshift Data API connectivity"""
    # TODO: Update these values when Redshift cluster is provisioned
    CLUSTER_IDENTIFIER = "your-redshift-cluster"  # UPDATE THIS
    DATABASE = "dev"                              # UPDATE THIS
    DB_USER = "awsuser"                          # UPDATE THIS
    
    try:
        hook = RedshiftDataHook()
        
        query_id = hook.execute_query(
            sql="SELECT current_timestamp as connection_test, current_user, current_database();",
            cluster_identifier=CLUSTER_IDENTIFIER,
            database=DATABASE,
            db_user=DB_USER
        )
        
        logging.info(f"Query executed successfully. Query ID: {query_id}")
        
        # Get results
        results = hook.get_query_results(query_id)
        logging.info(f"Query results: {results}")
        
        return "Redshift Data API test successful"
        
    except Exception as e:
        logging.error(f"Redshift Data API test failed: {str(e)}")
        raise

# Redshift test task - will fail until cluster details are updated
redshift_test = PythonOperator(
    task_id='test_redshift_data_api',
    python_callable=test_redshift_data_api,
    dag=dag
)

# Alternative using RedshiftDataOperator
redshift_query_task = RedshiftDataOperator(
    task_id='redshift_query_test',
    cluster_identifier='your-redshift-cluster',  # UPDATE THIS
    database='dev',                              # UPDATE THIS  
    db_user='awsuser',                          # UPDATE THIS
    sql='SELECT current_timestamp as query_time, \'Hello from MWAA!\' as message;',
    wait_for_completion=True,
    dag=dag
)

# Set dependencies
redshift_test >> redshift_query_task
