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
        self.kms_key = self._create_kms_key()
        self.security_group = self._create_security_group()
        self.execution_role = self._create_execution_role()
        self.mwaa_environment = self._create_mwaa_environment()
        
        self._create_outputs()

    def _validate_config(self):
        """Performs upfront validation of the provided configuration."""
        required_keys = ['name', 'dags_s3_bucket', 'environment_class']
        for key in required_keys:
            if key not in self.mwaa_config:
                raise ValueError(f"Missing required MWAA config: {key}")
      
    def _create_source_bucket(self) -> s3.Bucket:
        """
        Creates a versioned S3 bucket for MWAA source code and initializes
        the necessary folder structure for the data team to use.
        """
        print("Creating S3 source bucket...")
        bucket = s3.Bucket(
            self,
            "MwaaSourceBucket",
            bucket_name=self.mwaa_config["dags_s3_bucket"],
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # Create empty directory locally if it doesn't exist
        empty_dir = "./empty"
        os.makedirs(empty_dir, exist_ok=True)
        
        # Create an empty file in the empty directory to ensure it's not completely empty
        # (some versions of CDK have issues with completely empty directories)
        with open(os.path.join(empty_dir, ".placeholder"), "w") as f:
            f.write("# This is a placeholder file for the empty directory\n")

        # Create the baseline folder structure in S3
        # These folders will be used by the data team's pipeline
        folders = ["dags/", "plugins/", "requirements/"]
        
        for folder in folders:
            s3_deployment.BucketDeployment(
                self, 
                f"Create{folder.strip('/')}Folder",
                sources=[s3_deployment.Source.asset(empty_dir)],
                destination_bucket=bucket,
                destination_key_prefix=folder,
                retain_on_delete=True  # Keep folders when stack is deleted
            )
            
            # Create placeholder files for requirements.txt and plugins.zip
            if folder == "requirements/":
                with open(os.path.join(empty_dir, "requirements.txt"), "w") as f:
                    f.write("# Placeholder requirements.txt for MWAA\n")
                s3_deployment.BucketDeployment(
                    self,
                    "CreateRequirementsFile",
                    sources=[s3_deployment.Source.asset(empty_dir)],
                    destination_bucket=bucket,
                    destination_key_prefix="requirements",
                    retain_on_delete=True
                )
                
        return bucket

    def _create_kms_key(self) -> kms.Key:
        """Creates a customer-managed KMS key for encrypting MWAA environment data."""
        print("Creating KMS key...")
        return kms.Key(
            self, 
            f"{self.mwaa_config['name']}Key", 
            enable_key_rotation=True,
            policy=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        actions=[
                            "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", 
                            "kms:Put*", "kms:Decrypt*", "kms:Update*", "kms:Revoke*", 
                            "kms:Disable*", "kms:Get*", "kms:Delete*", 
                            "kms:ScheduleKeyDeletion", "kms:GenerateDataKey*", 
                            "kms:CancelKeyDeletion"
                        ],
                        principals=[iam.AccountRootPrincipal()],
                        resources=["*"]
                    ),
                    iam.PolicyStatement(
                        actions=[
                            "kms:Decrypt*", "kms:Describe*", "kms:GenerateDataKey*", 
                            "kms:Encrypt*", "kms:ReEncrypt*", "kms:PutKeyPolicy"
                        ],
                        effect=iam.Effect.ALLOW,
                        resources=["*"],
                        principals=[iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")],
                        conditions={
                            "ArnLike": {
                                "kms:EncryptionContext:aws:logs:arn": f"arn:aws:logs:{self.region}:{self.account}:*"
                            }
                        }
                    )
                ]
            ),
            description=f"KMS Key for MWAA Environment {self.mwaa_config['name']}"
        )

    def _create_security_group(self) -> ec2.SecurityGroup:
        """Creates a dedicated security group for the MWAA environment."""
        print("Creating security group...")
        vpc = ec2.Vpc.from_lookup(
            self, 
            "ExistingVPC", 
            vpc_id=self.vpc_config['id']
        )
        
        security_group = ec2.SecurityGroup(
            self, 
            "mwaa-sg",
            vpc=vpc,
            security_group_name=f"{self.mwaa_config['name']}-sg",
            description=f"Security Group for MWAA Environment {self.mwaa_config['name']}"
        )
        
        security_group.connections.allow_internally(
            ec2.Port.all_traffic(), 
            "Allow internal MWAA component communication"
        )
        
        return security_group

    def _create_execution_role(self) -> iam.Role:
        """Creates the IAM execution role that MWAA assumes to access other AWS services."""
        print("Creating MWAA execution role...")
        
        mwaa_policy_document = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    actions=["airflow:PublishMetrics"],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:airflow:{self.region}:{self.account}:environment/{self.mwaa_config['name']}"]
                ),
                iam.PolicyStatement(
                    actions=["s3:ListAllMyBuckets"],
                    effect=iam.Effect.DENY,
                    resources=["*"]
                ),
                iam.PolicyStatement(
                    actions=["s3:GetObject*", "s3:GetBucket*", "s3:List*"],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        self.source_bucket.bucket_arn,
                        self.source_bucket.arn_for_objects("*")
                    ]
                ),
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogStream", "logs:CreateLogGroup", "logs:PutLogEvents",
                        "logs:GetLogEvents", "logs:GetLogRecord", "logs:GetLogGroupFields",
                        "logs:GetQueryResults", "logs:DescribeLogGroups"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:logs:{self.region}:{self.account}:log-group:airflow-{self.mwaa_config['name']}-*"]
                ),
                iam.PolicyStatement(
                    actions=["logs:DescribeLogGroups"],
                    effect=iam.Effect.ALLOW,
                    resources=["*"]
                ),
                iam.PolicyStatement(
                    actions=[
                        "sqs:ChangeMessageVisibility", "sqs:DeleteMessage", 
                        "sqs:GetQueueAttributes", "sqs:GetQueueUrl", 
                        "sqs:ReceiveMessage", "sqs:SendMessage"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:sqs:{self.region}:*:airflow-celery-*"]
                ),
                iam.PolicyStatement(
                    actions=["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey*", "kms:Encrypt"],
                    effect=iam.Effect.ALLOW,
                    resources=[self.kms_key.key_arn],
                    conditions={
                        "StringEquals": {
                            "kms:ViaService": [
                                f"sqs.{self.region}.amazonaws.com",
                                f"s3.{self.region}.amazonaws.com"
                            ]
                        }
                    }
                )
            ]
        )
        
        # Add Redshift permissions if redshift config exists
        if self.redshift_config:
            mwaa_policy_document.add_statements(
                iam.PolicyStatement(
                    actions=["redshift:DescribeClusters", "redshift:GetClusterCredentials", "redshift-data:*"],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f"arn:aws:redshift:{self.region}:{self.account}:cluster:{self.redshift_config['cluster_identifier']}",
                        f"arn:aws:redshift:{self.region}:{self.account}:dbname:{self.redshift_config['cluster_identifier']}/{self.redshift_config['database_name']}",
                        f"arn:aws:redshift:{self.region}:{self.account}:dbuser:{self.redshift_config['cluster_identifier']}/*"
                    ]
                )
            )
        
        return iam.Role(
            self, 
            "mwaa-service-role",
            role_name=f"{self.mwaa_config['name']}-execution-role",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("airflow.amazonaws.com"),
                iam.ServicePrincipal("airflow-env.amazonaws.com")
            ),
            inline_policies={"CDKmwaaPolicyDocument": mwaa_policy_document},
            path="/service-role/"
        )

    def _create_mwaa_environment(self) -> mwaa.CfnEnvironment:
        """
        Creates the main MWAA Environment with the proper configuration.
        """
        print("Creating MWAA environment...")

        # Set default folder paths that correspond to the empty folders we created
        dag_s3_path = self.mwaa_config.get('dags_folder', 'dags')
        requirements_s3_path = self.mwaa_config.get('requirements_file', 'requirements/requirements.txt')
        plugins_s3_path = self.mwaa_config.get('plugins_file', 'plugins/plugins.zip')

        # Create the MWAA environment
        managed_airflow = mwaa.CfnEnvironment(
            self, 'MWAAEnvironment',
            name=self.mwaa_config['name'],
            execution_role_arn=self.execution_role.role_arn,
            source_bucket_arn=self.source_bucket.bucket_arn,
            dag_s3_path=dag_s3_path,
            requirements_s3_path=requirements_s3_path,
            plugins_s3_path=plugins_s3_path,
            airflow_version=self.mwaa_config.get('airflow_version', '2.7.2'),
            environment_class=self.mwaa_config.get('environment_class', 'mw1.small'),
            kms_key=self.kms_key.key_arn,
            max_workers=self.mwaa_config.get('max_workers', 5),
            min_workers=self.mwaa_config.get('min_workers', 1),
            schedulers=self.mwaa_config.get('schedulers', 2),
            webserver_access_mode=self.mwaa_config.get('webserver_access_mode', 'PRIVATE_ONLY'),
            weekly_maintenance_window_start=self.mwaa_config.get('weekly_maintenance_window_start')
        )

        # Configure network settings
        managed_airflow.add_override(
            'Properties.NetworkConfiguration', 
            {
                "SecurityGroupIds": [self.security_group.security_group_id], 
                "SubnetIds": self.vpc_config['private_subnet_ids']
            }
        )
        
        # Configure logging
        logging_config = {
            "DagProcessingLogs": {"Enabled": True, "LogLevel": "INFO"},
            "SchedulerLogs": {"Enabled": True, "LogLevel": "INFO"},
            "TaskLogs": {"Enabled": True, "LogLevel": "INFO"},
            "WebserverLogs": {"Enabled": True, "LogLevel": "INFO"},
            "WorkerLogs": {"Enabled": True, "LogLevel": "INFO"}
        }
        
        # Override with any custom logging config if provided
        if 'logging' in self.mwaa_config:
            for log_type, config in self.mwaa_config['logging'].items():
                if log_type == 'Task':
                    logging_config["TaskLogs"] = {"Enabled": config.get('enabled', True), "LogLevel": config.get('log_level', 'INFO')}
                elif log_type == 'WebServer':
                    logging_config["WebserverLogs"] = {"Enabled": config.get('enabled', True), "LogLevel": config.get('log_level', 'INFO')}
                elif log_type == 'Scheduler':
                    logging_config["SchedulerLogs"] = {"Enabled": config.get('enabled', True), "LogLevel": config.get('log_level', 'INFO')}
                elif log_type == 'Worker':
                    logging_config["WorkerLogs"] = {"Enabled": config.get('enabled', True), "LogLevel": config.get('log_level', 'INFO')}
                elif log_type == 'DAGProcessing':
                    logging_config["DagProcessingLogs"] = {"Enabled": config.get('enabled', True), "LogLevel": config.get('log_level', 'INFO')}
        
        managed_airflow.add_override('Properties.LoggingConfiguration', logging_config)
        
        # Configure Airflow settings
        airflow_config_options = self.mwaa_config.get('airflow_configuration_options', {})
        airflow_config_options.update({'core.default_timezone': 'utc'})
        managed_airflow.add_override('Properties.AirflowConfigurationOptions', airflow_config_options)
        
        # Configure endpoint management
        endpoint_mgmt = self.mwaa_config.get('endpoint_management', 'SERVICE')
        managed_airflow.add_override('Properties.EndpointManagement', endpoint_mgmt)
        
        # Add tags
        tags = {'env': self.env_name, 'service': 'MWAA Apache AirFlow'}
        if 'tags' in self.env_config:
            tags.update(self.env_config['tags'])
        managed_airflow.add_override('Properties.Tags', tags)

        return managed_airflow

    def _create_outputs(self):
        """Creates CloudFormation outputs for easy access to resource identifiers."""
        print("Creating CloudFormation outputs...")
        
        # Basic outputs
        CfnOutput(
            self, 
            "MWAAEnvironmentName", 
            value=self.mwaa_environment.name, 
            description="Name of the MWAA Environment"
        )
        
        CfnOutput(
            self, 
            "MWAAWebserverUrl", 
            value=self.mwaa_environment.attr_webserver_url, 
            description="URL for the Airflow UI"
        )
        
        CfnOutput(
            self, 
            "S3BucketName", 
            value=self.source_bucket.bucket_name, 
            description="S3 bucket for DAGs, requirements, and plugins"
        )
        
        # Additional outputs to help the data team's CI/CD pipeline
        CfnOutput(
            self, 
            "DagsS3Path", 
            value=f"s3://{self.source_bucket.bucket_name}/{self.mwaa_config.get('dags_folder', 'dags')}", 
            description="S3 path for DAGs"
        )
        
        CfnOutput(
            self, 
            "PluginsS3Path", 
            value=f"s3://{self.source_bucket.bucket_name}/{self.mwaa_config.get('plugins_file', 'plugins/plugins.zip')}", 
            description="S3 path for plugins"
        )
        
        CfnOutput(
            self, 
            "RequirementsS3Path", 
            value=f"s3://{self.source_bucket.bucket_name}/{self.mwaa_config.get('requirements_file', 'requirements/requirements.txt')}", 
            description="S3 path for requirements"
        )
        
        # Output IAM role ARN for the data team
        CfnOutput(
            self, 
            "MWAAExecutionRoleARN", 
            value=self.execution_role.role_arn, 
            description="IAM Role ARN for MWAA execution"
        )