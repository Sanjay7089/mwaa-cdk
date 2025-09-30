from aws_cdk import (
    Stack,
    aws_s3 as s3,
    aws_s3_deployment as s3_deployment,
    RemovalPolicy,
    CfnOutput
)
from constructs import Construct

class AirflowSourceStack(Stack):
    """
    Stack to create S3 bucket and deploy DAGs, requirements, and plugins
    """

    def __init__(self, scope: Construct, construct_id: str, bucket_name: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create S3 bucket for MWAA source code with versioning
        self.source_bucket = s3.Bucket(
            self,
            "MwaaSourceBucket",
            bucket_name=bucket_name,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.DESTROY,  # For POC - change for production
            auto_delete_objects=True  # For POC - change for production
        )

        # Deploy DAG code to S3 Bucket
        s3_deployment.BucketDeployment(
            self,
            "MwaaSourceBucketDagsDeployment",
            sources=[s3_deployment.Source.asset("./dags")],
            destination_bucket=self.source_bucket,
            destination_key_prefix="dags",
            retain_on_delete=False  # For POC - change for production
        )

        # Deploy requirements to S3 Bucket
        s3_deployment.BucketDeployment(
            self,
            "MwaaSourceRequirementsDeployment",
            sources=[s3_deployment.Source.asset("./requirements")],
            destination_bucket=self.source_bucket,
            destination_key_prefix="requirements",
            retain_on_delete=False  # For POC - change for production
        )

        # Deploy plugins to S3 Bucket (if exists)
        try:
            s3_deployment.BucketDeployment(
                self,
                "MwaaSourcePluginsDeployment",
                sources=[s3_deployment.Source.asset("./plugins")],
                destination_bucket=self.source_bucket,
                destination_key_prefix="plugins",
                retain_on_delete=False  # For POC - change for production
            )
        except:
            # Plugins folder might not exist, which is fine
            pass

        # Output the bucket name and ARN
        CfnOutput(
            self,
            "SourceBucketName",
            value=self.source_bucket.bucket_name,
            description="S3 Bucket name for MWAA source code"
        )
        
        CfnOutput(
            self,
            "SourceBucketArn",
            value=self.source_bucket.bucket_arn,
            description="S3 Bucket ARN for MWAA source code"
        )
