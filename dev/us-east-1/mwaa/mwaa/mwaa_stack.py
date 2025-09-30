from aws_cdk import (
    Stack,
    aws_s3 as s3,
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_mwaa as mwaa,
    Environment,
    CfnOutput
)
from constructs import Construct
from typing import Dict, Any

class MwaaStack(Stack):
    """
    MWAA Stack with Redshift integration support
    Uses existing VPC and follows best practices for security and permissions
    """

    def __init__(
            self, 
            scope: Construct, 
            construct_id: str, 
            source_bucket: s3.Bucket,
            mwaa_config: Dict[str, Any],
            vpc_config: Dict[str, Any],
            **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Load configuration
        self.mwaa_config = mwaa_config
        self.vpc_config = vpc_config
        
        # Import existing VPC
        self.vpc = ec2.Vpc.from_lookup(
            self,
            "ExistingVpc",
            vpc_id=vpc_config["id"]
        )
        
        # Import existing private subnets
        self.private_subnets = []
        for i, subnet_id in enumerate(vpc_config["private_subnet_ids"]):
            subnet = ec2.Subnet.from_subnet_id(
                self,
                f"PrivateSubnet{i}",
                subnet_id
            )
            self.private_subnets.append(subnet)

        # Create MWAA execution role with comprehensive permissions
        self.mwaa_execution_role = self._create_mwaa_execution_role(source_bucket)
        
        # Create security group for MWAA
        self.mwaa_security_group = self._create_mwaa_security_group()
        
        # Create MWAA environment (removed log group creation)
        self.mwaa_environment = self._create_mwaa_environment(source_bucket)
        
        # Output important values
        self._create_outputs()

    def _create_mwaa_execution_role(self, source_bucket: s3.Bucket) -> iam.Role:
        """Create IAM role for MWAA execution with Redshift permissions"""
        
        # Create execution role
        execution_role = iam.Role(
            self,
            "MwaaExecutionRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("airflow.amazonaws.com"),
                iam.ServicePrincipal("airflow-env.amazonaws.com")
            ),
            inline_policies={
                "MwaaExecutionPolicy": self._create_mwaa_execution_policy(source_bucket)
            },
            path="/service-role/"
        )

        return execution_role

    def _create_mwaa_execution_policy(self, source_bucket: s3.Bucket) -> iam.PolicyDocument:
        """Create comprehensive IAM policy for MWAA execution including Redshift permissions"""
        
        source_bucket_arn = source_bucket.bucket_arn
        
        return iam.PolicyDocument(
            statements=[
                # Airflow metrics
                iam.PolicyStatement(
                    actions=["airflow:PublishMetrics"],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:airflow:{self.region}:{self.account}:environment/{self.mwaa_config['name']}"]
                ),
                
                # S3 permissions for DAGs bucket
                iam.PolicyStatement(
                    actions=[
                        "s3:GetObject*",
                        "s3:GetBucket*",
                        "s3:List*"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        source_bucket_arn,
                        f"{source_bucket_arn}/*"
                    ]
                ),
                
                # CloudWatch Logs - Allow MWAA to create and manage log groups
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:GetLogEvents",
                        "logs:GetLogRecord",
                        "logs:GetLogGroupFields",
                        "logs:GetQueryResults",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:logs:{self.region}:{self.account}:*"]
                ),
                
                # CloudWatch Metrics
                iam.PolicyStatement(
                    actions=["cloudwatch:PutMetricData"],
                    effect=iam.Effect.ALLOW,
                    resources=["*"]
                ),
                
                # SQS for Celery
                iam.PolicyStatement(
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
                
                # Secrets Manager for Airflow connections and variables
                iam.PolicyStatement(
                    actions=[
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:PutSecretValue",
                        "secretsmanager:CreateSecret",
                        "secretsmanager:UpdateSecret",
                        "secretsmanager:DeleteSecret"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:airflow/connections/*",
                        f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:airflow/variables/*"
                    ]
                ),
                
                # Redshift permissions for connectivity and operations
                iam.PolicyStatement(
                    actions=[
                        "redshift:DescribeClusters",
                        "redshift:GetClusterCredentials",
                        "redshift:DescribeClusterSubnetGroups",
                        "redshift:DescribeClusterSecurityGroups",
                        "redshift:DescribeClusterParameters",
                        "redshift:DescribeClusterParameterGroups"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:redshift:{self.region}:{self.account}:cluster:*"]
                ),
                
                # Redshift Data API permissions
                iam.PolicyStatement(
                    actions=[
                        "redshift-data:ExecuteStatement",
                        "redshift-data:DescribeStatement",
                        "redshift-data:GetStatementResult",
                        "redshift-data:ListStatements",
                        "redshift-data:CancelStatement",
                        "redshift-data:ListDatabases",
                        "redshift-data:ListSchemas",
                        "redshift-data:ListTables",
                        "redshift-data:DescribeTable"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=["*"]
                ),
                
                # KMS permissions
                iam.PolicyStatement(
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
                                f"s3.{self.region}.amazonaws.com",
                                f"secretsmanager.{self.region}.amazonaws.com"
                            ]
                        }
                    }
                ),
                
                # ECS permissions for task execution
                iam.PolicyStatement(
                    actions=[
                        "ecs:RunTask",
                        "ecs:DescribeTasks",
                        "ecs:RegisterTaskDefinition",
                        "ecs:DescribeTaskDefinition",
                        "ecs:ListTasks"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=["*"]
                ),
                
                # IAM PassRole for ECS tasks
                iam.PolicyStatement(
                    actions=["iam:PassRole"],
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                    conditions={
                        "StringLike": {
                            "iam:PassedToService": "ecs-tasks.amazonaws.com"
                        }
                    }
                )
            ]
        )

    def _create_mwaa_security_group(self) -> ec2.SecurityGroup:
        """Create security group for MWAA"""
        
        security_group = ec2.SecurityGroup(
            self,
            "MwaaSecurityGroup",
            vpc=self.vpc,
            description="Security group for MWAA environment",
            security_group_name=f"{self.mwaa_config['name']}-sg",
            allow_all_outbound=False
        )
        
        # Allow internal communication
        security_group.add_ingress_rule(
            peer=security_group,
            connection=ec2.Port.all_traffic(),
            description="Allow internal MWAA communication"
        )
        
        # Allow HTTPS outbound for accessing AWS services
        security_group.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(443),
            description="HTTPS outbound for AWS services"
        )
        
        # Allow HTTP outbound for package downloads
        security_group.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(80),
            description="HTTP outbound for package downloads"
        )
        
        # Allow DNS outbound
        security_group.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.udp(53),
            description="DNS outbound"
        )
        
        return security_group

    def _create_mwaa_environment(self, source_bucket: s3.Bucket) -> mwaa.CfnEnvironment:
        """Create the MWAA environment - let MWAA create log groups automatically"""
        
        # Prepare environment configuration
        env_config = {
            "name": self.mwaa_config["name"],
            "source_bucket_arn": source_bucket.bucket_arn,
            "execution_role_arn": self.mwaa_execution_role.role_arn,
            "dag_s3_path": "dags",
            "requirements_s3_path": self.mwaa_config.get("requirements_s3_path"),
            "airflow_version": self.mwaa_config.get("airflow_version", "2.10.3"),
            "environment_class": self.mwaa_config.get("environment_class", "mw1.micro"),
            "max_workers": self.mwaa_config.get("max_workers", 1),
            "min_workers": self.mwaa_config.get("min_workers", 1),
            "webserver_access_mode": self.mwaa_config.get("webserver_access_mode", "PRIVATE_ONLY"),
            "network_configuration": mwaa.CfnEnvironment.NetworkConfigurationProperty(
                subnet_ids=self.vpc_config["private_subnet_ids"],
                security_group_ids=[self.mwaa_security_group.security_group_id]
            ),
            # Let MWAA create log groups automatically - don't specify logging_configuration
            "airflow_configuration_options": {
                "core.load_examples": "False",
                "core.dags_are_paused_at_creation": "False",
                "logging.logging_level": "INFO",
                "webserver.expose_config": "True"
            }
        }
        
        # Only add plugins_s3_path if it's specified in config
        if self.mwaa_config.get("plugins_s3_path"):
            env_config["plugins_s3_path"] = self.mwaa_config.get("plugins_s3_path")
        
        environment = mwaa.CfnEnvironment(
            self,
            "MwaaEnvironment",
            **env_config
        )
        
        # Add dependencies (removed log group dependencies)
        environment.node.add_dependency(self.mwaa_execution_role)
        environment.node.add_dependency(self.mwaa_security_group)
        
        return environment

    def _create_outputs(self):
        """Create CloudFormation outputs"""
        
        CfnOutput(
            self,
            "MwaaEnvironmentName",
            value=self.mwaa_environment.name,
            description="MWAA Environment Name"
        )
        
        CfnOutput(
            self,
            "MwaaExecutionRoleArn",
            value=self.mwaa_execution_role.role_arn,
            description="MWAA Execution Role ARN"
        )
        
        CfnOutput(
            self,
            "MwaaSecurityGroupId",
            value=self.mwaa_security_group.security_group_id,
            description="MWAA Security Group ID"
        )
        
        CfnOutput(
            self,
            "VpcId",
            value=self.vpc.vpc_id,
            description="VPC ID used by MWAA"
        )
