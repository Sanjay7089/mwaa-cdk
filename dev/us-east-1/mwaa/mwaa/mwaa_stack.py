from aws_cdk import (
    Stack,
    aws_s3 as s3,
    aws_s3_deployment as s3_deployment,
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_mwaa as mwaa,
    aws_logs as logs,
    CfnOutput,
    RemovalPolicy
)
from constructs import Construct
from typing import Dict, Any
import os

class MwaaStack(Stack):
    """
    Complete MWAA Stack with S3 bucket, file deployment, IAM roles, and MWAA environment
    Ensures proper resource creation order
    """

    def __init__(
            self, 
            scope: Construct, 
            construct_id: str, 
            mwaa_config: Dict[str, Any],
            vpc_config: Dict[str, Any],
            **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Store configuration
        self.mwaa_config = mwaa_config
        self.vpc_config = vpc_config
        
        # Step 1: Create S3 bucket for MWAA source code
        self.source_bucket = self._create_source_bucket()
        
        # Step 2: Deploy files to S3 (DAGs, requirements, plugins)
        self._deploy_files_to_s3()
        
        # Step 3: Import existing VPC and subnets
        self._import_vpc_resources()
        
        # Step 4: Create security group for MWAA
        self.mwaa_security_group = self._create_mwaa_security_group()
        
        # Step 5: Create IAM execution role
        self.mwaa_execution_role = self._create_mwaa_execution_role()
        
        # Step 6: Create CloudWatch log groups
        self.log_groups = self._create_log_groups()
        
        # Step 7: Create MWAA environment (depends on S3 deployments)
        self.mwaa_environment = self._create_mwaa_environment()
        
        # Step 8: Create outputs
        self._create_outputs()

    def _create_source_bucket(self) -> s3.Bucket:
        """Create S3 bucket for MWAA source code with versioning"""
        
        bucket = s3.Bucket(
            self,
            "MwaaSourceBucket",
            bucket_name=self.mwaa_config["dags_s3_bucket"],
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )
        
        return bucket

    def _deploy_files_to_s3(self):
        """Deploy DAGs, requirements, and plugins to S3"""
        
        # Deploy DAGs
        if os.path.exists("./dags"):
            self.dags_deployment = s3_deployment.BucketDeployment(
                self,
                "DeployDags",
                sources=[s3_deployment.Source.asset("./dags")],
                destination_bucket=self.source_bucket,
                destination_key_prefix="dags",
                prune=False,
                retain_on_delete=False
            )
        
        # Deploy requirements
        if os.path.exists("./requirements"):
            self.requirements_deployment = s3_deployment.BucketDeployment(
                self,
                "DeployRequirements",
                sources=[s3_deployment.Source.asset("./requirements")],
                destination_bucket=self.source_bucket,
                destination_key_prefix="requirements",
                prune=False,
                retain_on_delete=False
            )
        
        # Deploy plugins (if exists and configured)
        if self.mwaa_config.get("plugins_s3_path") and os.path.exists("./plugins"):
            # Check if plugins folder has files other than __init__.py
            plugin_files = [f for f in os.listdir("./plugins") if f != "__init__.py" and not f.startswith(".")]
            if plugin_files:
                self.plugins_deployment = s3_deployment.BucketDeployment(
                    self,
                    "DeployPlugins",
                    sources=[s3_deployment.Source.asset("./plugins")],
                    destination_bucket=self.source_bucket,
                    destination_key_prefix="plugins",
                    prune=False,
                    retain_on_delete=False
                )

    def _import_vpc_resources(self):
        """Import existing VPC and private subnets"""
        
        # Import VPC
        self.vpc = ec2.Vpc.from_lookup(
            self,
            "ExistingVpc",
            vpc_id=self.vpc_config["id"]
        )
        
        # Import private subnets
        self.private_subnets = []
        for i, subnet_id in enumerate(self.vpc_config["private_subnet_ids"]):
            subnet = ec2.Subnet.from_subnet_id(
                self,
                f"PrivateSubnet{i}",
                subnet_id
            )
            self.private_subnets.append(subnet)

    def _create_mwaa_security_group(self) -> ec2.SecurityGroup:
        """Create security group for MWAA with self-referencing rule"""
        
        security_group = ec2.SecurityGroup(
            self,
            "MwaaSecurityGroup",
            vpc=self.vpc,
            description=f"Security group for MWAA environment {self.mwaa_config['name']}",
            security_group_name=f"{self.mwaa_config['name']}-sg",
            allow_all_outbound=True
        )
        
        # Self-referencing rule for internal MWAA communication
        security_group.add_ingress_rule(
            peer=security_group,
            connection=ec2.Port.all_traffic(),
            description="Allow internal MWAA communication"
        )
        
        return security_group

    def _create_mwaa_execution_role(self) -> iam.Role:
        """Create IAM role for MWAA execution with comprehensive permissions"""
        
        # Create execution role
        execution_role = iam.Role(
            self,
            "MwaaExecutionRole",
            role_name=f"{self.mwaa_config['name']}-execution-role",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("airflow.amazonaws.com"),
                iam.ServicePrincipal("airflow-env.amazonaws.com")
            ),
            path="/service-role/"
        )

        # Add inline policy with all required permissions
        execution_role.attach_inline_policy(
            iam.Policy(
                self,
                "MwaaExecutionPolicy",
                policy_name="MwaaExecutionPolicy",
                document=self._create_execution_policy_document()
            )
        )

        return execution_role

    def _create_execution_policy_document(self) -> iam.PolicyDocument:
        """Create comprehensive IAM policy document for MWAA execution"""
        
        return iam.PolicyDocument(
            statements=[
                # Airflow environment metrics
                iam.PolicyStatement(
                    sid="AllowAirflowMetrics",
                    actions=["airflow:PublishMetrics"],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:airflow:{self.region}:{self.account}:environment/{self.mwaa_config['name']}"]
                ),
                
                # S3 permissions for DAGs bucket
                iam.PolicyStatement(
                    sid="AllowS3Access",
                    actions=[
                        "s3:GetObject*",
                        "s3:GetBucket*",
                        "s3:List*",
                        "s3:PutObject",
                        "s3:PutObjectAcl"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        self.source_bucket.bucket_arn,
                        f"{self.source_bucket.bucket_arn}/*"
                    ]
                ),
                
                # CloudWatch Logs permissions
                iam.PolicyStatement(
                    sid="AllowCloudWatchLogs",
                    actions=[
                        "logs:CreateLogStream",
                        "logs:CreateLogGroup",
                        "logs:PutLogEvents",
                        "logs:GetLogEvents",
                        "logs:GetLogRecord",
                        "logs:GetLogGroupFields",
                        "logs:GetQueryResults",
                        "logs:DescribeLogGroups"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:logs:{self.region}:{self.account}:log-group:airflow-{self.mwaa_config['name']}*"]
                ),
                
                # CloudWatch Metrics
                iam.PolicyStatement(
                    sid="AllowCloudWatchMetrics",
                    actions=["cloudwatch:PutMetricData"],
                    effect=iam.Effect.ALLOW,
                    resources=["*"]
                ),
                
                # SQS for Celery executor
                iam.PolicyStatement(
                    sid="AllowSQS",
                    actions=[
                        "sqs:ChangeMessageVisibility",
                        "sqs:DeleteMessage",
                        "sqs:GetQueueAttributes",
                        "sqs:GetQueueUrl",
                        "sqs:ReceiveMessage",
                        "sqs:SendMessage"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:sqs:{self.region}:*:airflow-celery-*"]
                ),
                
                # KMS permissions for encryption
                iam.PolicyStatement(
                    sid="AllowKMS",
                    actions=[
                        "kms:Decrypt",
                        "kms:DescribeKey",
                        "kms:GenerateDataKey*",
                        "kms:Encrypt"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    conditions={
                        "StringEquals": {
                            "kms:ViaService": [
                                f"sqs.{self.region}.amazonaws.com",
                                f"s3.{self.region}.amazonaws.com"
                            ]
                        }
                    }
                ),
                
                # Secrets Manager for connections and variables
                iam.PolicyStatement(
                    sid="AllowSecretsManager",
                    actions=[
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:DescribeSecret"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:airflow/*"
                    ]
                ),
                
                # Redshift Serverless permissions
                iam.PolicyStatement(
                    sid="AllowRedshiftServerless",
                    actions=[
                        "redshift-serverless:GetWorkgroup",
                        "redshift-serverless:GetNamespace",
                        "redshift-serverless:GetCredentials"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f"arn:aws:redshift-serverless:{self.region}:{self.account}:workgroup/*",
                        f"arn:aws:redshift-serverless:{self.region}:{self.account}:namespace/*"
                    ]
                ),
                
                # Redshift Data API permissions
                iam.PolicyStatement(
                    sid="AllowRedshiftDataAPI",
                    actions=[
                        "redshift-data:ExecuteStatement",
                        "redshift-data:DescribeStatement",
                        "redshift-data:CancelStatement",
                        "redshift-data:GetStatementResult",
                        "redshift-data:ListStatements",
                        "redshift-data:ListDatabases",
                        "redshift-data:ListSchemas",
                        "redshift-data:ListTables",
                        "redshift-data:DescribeTable"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=["*"]
                ),
                
                # EC2 permissions for network interfaces (required for VPC)
                iam.PolicyStatement(
                    sid="AllowEC2NetworkAccess",
                    actions=[
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeVpcs"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=["*"]
                )
            ]
        )

    def _create_log_groups(self) -> Dict[str, logs.LogGroup]:
        """Create CloudWatch log groups for MWAA components"""
        
        log_groups = {}
        log_components = {
            "DAGProcessing": "dag-processing",
            "Scheduler": "scheduler",
            "Task": "task",
            "Worker": "worker",
            "WebServer": "webserver"
        }
        
        for component_name, log_type in log_components.items():
            log_groups[log_type] = logs.LogGroup(
                self,
                f"MwaaLogGroup{component_name}",
                log_group_name=f"airflow-{self.mwaa_config['name']}-{log_type}",
                retention=logs.RetentionDays.ONE_WEEK,
                removal_policy=RemovalPolicy.DESTROY
            )
        
        return log_groups

    def _create_mwaa_environment(self) -> mwaa.CfnEnvironment:
        """Create the MWAA environment with all configurations"""
        
        # Prepare network configuration
        network_config = mwaa.CfnEnvironment.NetworkConfigurationProperty(
            subnet_ids=self.vpc_config["private_subnet_ids"],
            security_group_ids=[self.mwaa_security_group.security_group_id]
        )
        
        # Prepare logging configuration
        logging_config = mwaa.CfnEnvironment.LoggingConfigurationProperty(
            dag_processing_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                enabled=True,
                log_level="INFO"
            ),
            scheduler_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                enabled=True,
                log_level="INFO"
            ),
            task_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                enabled=True,
                log_level="INFO"
            ),
            worker_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                enabled=True,
                log_level="INFO"
            ),
            webserver_logs=mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                enabled=True,
                log_level="INFO"
            )
        )
        
        # Airflow configuration options
        airflow_config_options = {
            "core.load_examples": "False",
            "core.dags_are_paused_at_creation": "False",
            "logging.logging_level": "INFO",
            "webserver.expose_config": "True",
            "webserver.instance_name": self.mwaa_config['name']
        }
        
        # Determine if plugins should be included
        plugins_path = None
        if self.mwaa_config.get("plugins_s3_path"):
            if os.path.exists("./plugins"):
                plugin_files = [f for f in os.listdir("./plugins") if f != "__init__.py" and not f.startswith(".")]
                if plugin_files:
                    plugins_path = self.mwaa_config["plugins_s3_path"]
        
        # Create MWAA environment
        environment = mwaa.CfnEnvironment(
            self,
            "MwaaEnvironment",
            name=self.mwaa_config["name"],
            source_bucket_arn=self.source_bucket.bucket_arn,
            execution_role_arn=self.mwaa_execution_role.role_arn,
            dag_s3_path="dags",
            requirements_s3_path=self.mwaa_config.get("requirements_s3_path"),
            plugins_s3_path=plugins_path,
            airflow_version=self.mwaa_config["airflow_version"],
            environment_class=self.mwaa_config["environment_class"],
            max_workers=self.mwaa_config["max_workers"],
            min_workers=self.mwaa_config["min_workers"],
            webserver_access_mode=self.mwaa_config["webserver_access_mode"],
            network_configuration=network_config,
            logging_configuration=logging_config,
            airflow_configuration_options=airflow_config_options
        )
        
        # Add dependencies to ensure proper creation order
        environment.node.add_dependency(self.source_bucket)
        environment.node.add_dependency(self.mwaa_execution_role)
        environment.node.add_dependency(self.mwaa_security_group)
        
        # CRITICAL: Make MWAA depend on file deployments
        if hasattr(self, 'dags_deployment'):
            environment.node.add_dependency(self.dags_deployment)
        if hasattr(self, 'requirements_deployment'):
            environment.node.add_dependency(self.requirements_deployment)
        if hasattr(self, 'plugins_deployment'):
            environment.node.add_dependency(self.plugins_deployment)
        
        for log_group in self.log_groups.values():
            environment.node.add_dependency(log_group)
        
        return environment

    def _create_outputs(self):
        """Create CloudFormation outputs for important resources"""
        
        CfnOutput(
            self,
            "MwaaEnvironmentName",
            value=self.mwaa_environment.name,
            description="MWAA Environment Name",
            export_name=f"{self.stack_name}-environment-name"
        )
        
        CfnOutput(
            self,
            "MwaaSourceBucketName",
            value=self.source_bucket.bucket_name,
            description="S3 Bucket for MWAA source code (DAGs, requirements, plugins)",
            export_name=f"{self.stack_name}-source-bucket"
        )
        
        CfnOutput(
            self,
            "MwaaExecutionRoleArn",
            value=self.mwaa_execution_role.role_arn,
            description="MWAA Execution Role ARN",
            export_name=f"{self.stack_name}-execution-role-arn"
        )
        
        CfnOutput(
            self,
            "MwaaSecurityGroupId",
            value=self.mwaa_security_group.security_group_id,
            description="MWAA Security Group ID (add this to Redshift Serverless security group inbound rules)",
            export_name=f"{self.stack_name}-security-group-id"
        )
        
        CfnOutput(
            self,
            "MwaaWebServerUrl",
            value=f"https://{self.mwaa_environment.attr_webserver_url}",
            description="MWAA Web Server URL"
        )