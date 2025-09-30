from aws_cdk import (
    Stack,
    aws_ec2 as ec2
)
from constructs import Construct

class VpcStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, config: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc_config = config["vpc"]

        # Create VPC with public and private subnets
        self.vpc = ec2.Vpc(
            self,
            vpc_config["name"],
            ip_addresses=ec2.IpAddresses.cidr(vpc_config["cidr"]),
            max_azs=vpc_config["max_azs"],
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=vpc_config["public_subnet_cidr_mask"]
                ),
                ec2.SubnetConfiguration(
                    name="private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=vpc_config["private_subnet_cidr_mask"]
                ),
            ],
            enable_dns_hostnames=True,
            enable_dns_support=True
        )
