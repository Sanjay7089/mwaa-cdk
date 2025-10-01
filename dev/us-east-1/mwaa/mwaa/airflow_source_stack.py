# # mwaa/airflow_source_stack.py
# import os
# from constructs import Construct
# from aws_cdk import (
#     Stack,
#     aws_s3 as s3,
#     aws_s3_deployment as s3_deployment,
#     RemovalPolicy,
#     CfnOutput,
# )

# class AirflowSourceStack(Stack):
#     """
#     Create S3 bucket for MWAA source (dags/requirements/plugins) and deploy local assets.
#     For PoC we set removal_policy=DESTROY and auto_delete_objects=True — change for prod.
#     """

#     def __init__(self, scope: Construct, construct_id: str, bucket_name: str = None, **kwargs) -> None:
#         super().__init__(scope, construct_id, **kwargs)

#         # If user does not supply a bucket name, CDK will create a unique one
#         bucket_args = dict(
#             versioned=True,
#             block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
#             encryption=s3.BucketEncryption.S3_MANAGED,
#             removal_policy=RemovalPolicy.DESTROY,  # PoC only
#             auto_delete_objects=True,  # PoC only
#         )

#         if bucket_name:
#             # validate bucket name simple rules (lowercase)
#             bucket_args["bucket_name"] = bucket_name

#         self.source_bucket = s3.Bucket(self, "MwaaSourceBucket", **bucket_args)

#         # Deploy dags
#         if os.path.isdir("./dags"):
#             s3_deployment.BucketDeployment(
#                 self,
#                 "MwaaSourceBucketDagsDeployment",
#                 sources=[s3_deployment.Source.asset("./dags")],
#                 destination_bucket=self.source_bucket,
#                 destination_key_prefix="dags",
#                 retain_on_delete=False,
#             )

#         # Deploy requirements
#         if os.path.isdir("./requirements"):
#             s3_deployment.BucketDeployment(
#                 self,
#                 "MwaaSourceRequirementsDeployment",
#                 sources=[s3_deployment.Source.asset("./requirements")],
#                 destination_bucket=self.source_bucket,
#                 destination_key_prefix="requirements",
#                 retain_on_delete=False,
#             )

#         # Deploy plugins if folder exists
#         if os.path.isdir("./plugins"):
#             s3_deployment.BucketDeployment(
#                 self,
#                 "MwaaSourcePluginsDeployment",
#                 sources=[s3_deployment.Source.asset("./plugins")],
#                 destination_bucket=self.source_bucket,
#                 destination_key_prefix="plugins",
#                 retain_on_delete=False,
#             )

#         CfnOutput(self, "SourceBucketName", value=self.source_bucket.bucket_name)
#         CfnOutput(self, "SourceBucketArn", value=self.source_bucket.bucket_arn)
