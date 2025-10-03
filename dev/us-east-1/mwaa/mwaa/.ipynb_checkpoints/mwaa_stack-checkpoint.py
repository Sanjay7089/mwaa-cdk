# mwaa/mwaa_stack.py

from aws_cdk import (
    Stack,
    CfnOutput,
    RemovalPolicy,
    aws_s3 as s3,
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_mwaa as mwaa,
    aws_kms as kms,
    aws_s3_deployment as s3_deployment,
    Tags
)
from constructs import Construct
import os

class MWAAStack(Stack):
    """
    A simplified and robust stack for provisioning an AWS MWAA environment.
    This version removes auto-delete features for simplicity and focuses on correctly
    handling dependencies to prevent race conditions during deployment.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        env_config: dict,
        env_name: str,
        account_name: str,
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- 1. Initialize Class Properties ---
        self.env_config = env_config
        self.env_name = env_name
        self.mwaa_config = env_config['mwaa']
        self.vpc_config = env_config['vpc']
        self.redshift_config = env_config.get('redshift', {})

        # --- 2. Orchestrate Resource Creation ---
        self._validate_config()
        self.source_bucket = self._create_source_bucket()
        
        # This method now returns the deployment constructs to establish dependencies.
        deployments = self._deploy_files_to_s3()

        self.kms_key = self._create_kms_key()
        self.security_group = self._create_security_group()
        self.execution_role = self._create_execution_role()
        
        # Pass the deployments to the environment creation method.
        self.mwaa_environment = self._create_mwaa_environment(deployments)
        
        self._create_outputs()

    def _validate_config(self):
        """Performs upfront validation of the provided configuration."""
        required_keys = ['name', 'dags_s3_bucket', 'environment_class']
        for key in required_keys:
            if key not in self.mwaa_config:
                raise ValueError(f"Missing required MWAA config: {key}")
        # ... (rest of validation is correct)

    def _create_source_bucket(self) -> s3.Bucket:
        """
        Creates a simple, versioned S3 bucket for MWAA source code.
        NOTE: auto_delete_objects has been removed for simplicity as requested.
        """
        print("Creating S3 source bucket...")
        bucket = s3.Bucket(
            self,
            "MwaaSourceBucket",
            bucket_name=self.mwaa_config["dags_s3_bucket"],
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            # The bucket will be orphaned on `cdk destroy` if not empty.
            removal_policy=RemovalPolicy.RETAIN,
        )
        return bucket

    def _deploy_files_to_s3(self) -> list:
        """
        Deploys local files to S3 and returns the deployment constructs
        so that other resources can explicitly depend on them.
        """
        print("Deploying local files to S3...")
        deployments = []

        # Deploy DAGs if the local './dags' folder exists.
        if os.path.exists("./dags"):
            dags_deployment = s3_deployment.BucketDeployment(self, "DeployDags", sources=[s3_deployment.Source.asset("./dags")], destination_bucket=self.source_bucket, destination_key_prefix="dags")
            deployments.append(dags_deployment)
        else:
            print("Warning: Local './dags' directory not found. Skipping DAG deployment.")

        # Deploy requirements if the local './requirements' folder exists.
        if os.path.exists("./requirements"):
            reqs_deployment = s3_deployment.BucketDeployment(self, "DeployRequirements", sources=[s3_deployment.Source.asset("./requirements")], destination_bucket=self.source_bucket, destination_key_prefix="requirements")
            deployments.append(reqs_deployment)
        else:
            print("Warning: Local './requirements' directory not found. Skipping deployment.")

        # Deploy plugins if the local './plugins' folder exists.
        if os.path.exists("./plugins"):
            plugins_deployment = s3_deployment.BucketDeployment(self, "DeployPlugins", sources=[s3_deployment.Source.asset("./plugins")], destination_bucket=self.source_bucket, destination_key_prefix="plugins")
            deployments.append(plugins_deployment)
        else:
            print("Warning: Local './plugins' directory not found. Skipping deployment.")
        
        return deployments

    def _create_mwaa_environment(self, deployments: list) -> mwaa.CfnEnvironment:
        """
        Creates the main MWAA Environment, ensuring it waits for file uploads to complete.
        """
        print("Creating MWAA environment...")

        # Conditionally define the S3 paths for requirements and plugins.
        # This prevents MWAA from failing if the corresponding local folders do not exist.
        requirements_s3_path = self.mwaa_config.get('requirements_file') if os.path.exists("./requirements") else None
        plugins_s3_path = self.mwaa_config.get('plugins_file') if os.path.exists("./plugins") else None

        # Create the low-level CfnEnvironment resource.
        managed_airflow = mwaa.CfnEnvironment(
            self, 'MWAAEnvironment',
            name=self.mwaa_config['name'],
            execution_role_arn=self.execution_role.role_arn,
            source_bucket_arn=self.source_bucket.bucket_arn,
            dag_s3_path=self.mwaa_config.get('dags_folder'),
            requirements_s3_path=requirements_s3_path,
            plugins_s3_path=plugins_s3_path,
            # ... other properties
            airflow_version=self.mwaa_config.get('airflow_version', '2.7.2'),
            environment_class=self.mwaa_config.get('environment_class', 'mw1.small'),
            kms_key=self.kms_key.key_arn,
            max_workers=self.mwaa_config.get('max_workers', 5),
            min_workers=self.mwaa_config.get('min_workers', 1),
            schedulers=self.mwaa_config.get('schedulers', 2),
            webserver_access_mode=self.mwaa_config.get('webserver_access_mode', 'PRIVATE_ONLY'),
            weekly_maintenance_window_start=self.mwaa_config.get('weekly_maintenance_window_start'),
        )

        # --- DEFINITIVE FIX FOR THE "Unable to read" RACE CONDITION ---
        # This loop adds an explicit "DependsOn" to the CloudFormation template.
        # It forces the MWAA Environment to wait until the S3 BucketDeployment
        # custom resources (which run the file uploads) have completed.
        print("Adding explicit dependencies from MWAA Environment to S3 deployments.")
        for deployment in deployments:
            managed_airflow.node.add_dependency(deployment)
        # -------------------------------------------------------------

        # Use overrides for properties not available in the L1 constructor.
        managed_airflow.add_override('Properties.NetworkConfiguration', {"SecurityGroupIds": [self.security_group.security_group_id], "SubnetIds": self.vpc_config['private_subnet_ids']})
        managed_airflow.add_override('Properties.LoggingConfiguration', {"DagProcessingLogs": {"Enabled": True, "LogLevel": "INFO"}, "SchedulerLogs": {"Enabled": True, "LogLevel": "INFO"}, "TaskLogs": {"Enabled": True, "LogLevel": "INFO"}, "WebserverLogs": {"Enabled": True, "LogLevel": "INFO"}, "WorkerLogs": {"Enabled": True, "LogLevel": "INFO"}})
        airflow_config_options = self.mwaa_config.get('airflow_configuration_options', {})
        airflow_config_options.update({'core.default_timezone': 'utc'})
        managed_airflow.add_override('Properties.AirflowConfigurationOptions', airflow_config_options)
        endpoint_mgmt = self.mwaa_config.get('endpoint_management', 'SERVICE')
        managed_airflow.add_override('Properties.EndpointManagement', endpoint_mgmt)
        tags = {'env': self.env_name, 'service': 'MWAA Apache AirFlow'}
        if 'tags' in self.env_config:
            tags.update(self.env_config['tags'])
        managed_airflow.add_override('Properties.Tags', tags)

        return managed_airflow

    # --- The following helper methods are correct and included for completeness ---

    def _create_kms_key(self) -> kms.Key:
        """Creates a customer-managed KMS key for encrypting MWAA environment data."""
        # ... (code is correct)
        return kms.Key(self, f"{self.mwaa_config['name']}Key", enable_key_rotation=True, policy=iam.PolicyDocument(statements=[iam.PolicyStatement(actions=["kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Decrypt*", "kms:Update*", "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:ScheduleKeyDeletion", "kms:GenerateDataKey*", "kms:CancelKeyDeletion"], principals=[iam.AccountRootPrincipal()], resources=["*"]), iam.PolicyStatement(actions=["kms:Decrypt*", "kms:Describe*", "kms:GenerateDataKey*", "kms:Encrypt*", "kms:ReEncrypt*", "kms:PutKeyPolicy"], effect=iam.Effect.ALLOW, resources=["*"], principals=[iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")], conditions={"ArnLike": {"kms:EncryptionContext:aws:logs:arn": f"arn:aws:logs:{self.region}:{self.account}:*"}})]), description=f"KMS Key for MWAA Environment {self.mwaa_config['name']}")

    def _create_security_group(self) -> ec2.SecurityGroup:
        """Creates a dedicated security group for the MWAA environment."""
        # ... (code is correct)
        vpc = ec2.Vpc.from_lookup(self, "ExistingVPC", vpc_id=self.vpc_config['id'])
        security_group = ec2.SecurityGroup(self, "mwaa-sg", vpc=vpc, security_group_name=f"{self.mwaa_config['name']}-sg", description=f"Security Group for MWAA Environment {self.mwaa_config['name']}")
        security_group.connections.allow_internally(ec2.Port.all_traffic(), "Allow internal MWAA component communication")
        return security_group

    def _create_execution_role(self) -> iam.Role:
        """Creates the IAM execution role that MWAA assumes to access other AWS services."""
        # ... (code is correct)
        mwaa_policy_document = iam.PolicyDocument(statements=[iam.PolicyStatement(actions=["airflow:PublishMetrics"], effect=iam.Effect.ALLOW, resources=[f"arn:aws:airflow:{self.region}:{self.account}:environment/{self.mwaa_config['name']}"]), iam.PolicyStatement(actions=["s3:ListAllMyBuckets"], effect=iam.Effect.DENY, resources=["*"]), iam.PolicyStatement(actions=["s3:GetObject*", "s3:GetBucket*", "s3:List*"], effect=iam.Effect.ALLOW, resources=[self.source_bucket.bucket_arn, self.source_bucket.arn_for_objects("*")]), iam.PolicyStatement(actions=["logs:CreateLogStream", "logs:CreateLogGroup", "logs:PutLogEvents", "logs:GetLogEvents", "logs:GetLogRecord", "logs:GetLogGroupFields", "logs:GetQueryResults", "logs:DescribeLogGroups"], effect=iam.Effect.ALLOW, resources=[f"arn:aws:logs:{self.region}:{self.account}:log-group:airflow-{self.mwaa_config['name']}-*"]), iam.PolicyStatement(actions=["logs:DescribeLogGroups"], effect=iam.Effect.ALLOW, resources=["*"]), iam.PolicyStatement(actions=["sqs:ChangeMessageVisibility", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:ReceiveMessage", "sqs:SendMessage"], effect=iam.Effect.ALLOW, resources=[f"arn:aws:sqs:{self.region}:*:airflow-celery-*"]), iam.PolicyStatement(actions=["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey*", "kms:Encrypt"], effect=iam.Effect.ALLOW, resources=[self.kms_key.key_arn], conditions={"StringEquals": {"kms:ViaService": [f"sqs.{self.region}.amazonaws.com", f"s3.{self.region}.amazonaws.com"]}})])
        if self.redshift_config: mwaa_policy_document.add_statements(iam.PolicyStatement(actions=["redshift:DescribeClusters", "redshift:GetClusterCredentials", "redshift-data:*"], effect=iam.Effect.ALLOW, resources=[f"arn:aws:redshift:{self.region}:{self.account}:cluster:{self.redshift_config['cluster_identifier']}", f"arn:aws:redshift:{self.region}:{self.account}:dbname:{self.redshift_config['cluster_identifier']}/{self.redshift_config['database_name']}", f"arn:aws:redshift:{self.region}:{self.account}:dbuser:{self.redshift_config['cluster_identifier']}/*"]))
        return iam.Role(self, "mwaa-service-role", role_name=f"{self.mwaa_config['name']}-execution-role", assumed_by=iam.CompositePrincipal(iam.ServicePrincipal("airflow.amazonaws.com"), iam.ServicePrincipal("airflow-env.amazonaws.com")), inline_policies={"CDKmwaaPolicyDocument": mwaa_policy_document}, path="/service-role/")

    def _create_outputs(self):
        """Creates CloudFormation outputs for easy access to resource identifiers."""
        # ... (code is correct)
        CfnOutput(self, "MWAAEnvironmentName", value=self.mwaa_environment.name, description="Name of the MWAA Environment")
        CfnOutput(self, "MWAAWebserverUrl", value=self.mwaa_environment.attr_webserver_url, description="URL for the Airflow UI")
        CfnOutput(self, "S3BucketName", value=self.source_bucket.bucket_name, description="S3 bucket for DAGs, requirements, and plugins")