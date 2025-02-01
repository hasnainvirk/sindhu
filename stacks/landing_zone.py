"""
Landing Zone
"""

import os
import subprocess
import zipfile
from dotenv import load_dotenv
from aws_cdk import (
    Stack,
    aws_lambda as lambda_,
    aws_apigateway as apigateway,
    aws_secretsmanager as secretsmanager,
    aws_logs as logs,
    aws_kms as kms,
    aws_ec2 as ec2,
    aws_ssm as ssm,
    aws_iam as iam,
    aws_certificatemanager as acm,
    aws_route53 as route53,
    aws_route53_targets as targets53,
    Duration,
    RemovalPolicy,
    CfnOutput,
    Tags,
    SecretValue,
)
from constructs import Construct

# Load environment variables from .env file
load_dotenv()


class LandingZone(Stack):
    """
    Landing Zone
    """

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self.vpc = ec2.Vpc(
            self,
            "sindhu",
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="PublicSubnet", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="PrivateSubnet",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="IsolatedSubnet",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                ),
            ],
        )

        # Retrieve ClientID and ClientSecret from .env
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")

        if not client_id or not client_secret:
            raise ValueError("CLIENT_ID and CLIENT_SECRET must be set in the .env file")

        encryption_key = kms.Key(
            self,
            "OAuthSecretEncryptionKey",
        )

        # Store ClientID & ClientSecret Securely in AWS Secrets Manager

        oauth_secret = secretsmanager.Secret(
            self,
            "OAuthClientSecret",
            secret_name="OAuthClientCredentials",
            encryption_key=encryption_key,
            # revisit this, not ver secure
            secret_object_value={
                "CLIENT_ID": SecretValue.unsafe_plain_text(client_id),
                "CLIENT_SECRET": SecretValue.unsafe_plain_text(client_secret),
            },
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Define paths
        lambda_dir = "lambda/oauth_token"
        package_dir = os.path.join(lambda_dir, "package")
        zip_file_path = os.path.join(lambda_dir, "lambda.zip")

        # Ensure clean package directory
        if os.path.exists(package_dir):
            subprocess.run(f"rm -rf {package_dir}", shell=True, check=True)
        os.makedirs(package_dir, exist_ok=True)

        # Install dependencies into package directory
        subprocess.run(
            f"pip install -r {lambda_dir}/requirements.txt -t {package_dir}",
            shell=True,
            check=True,
        )

        # Create ZIP package using zipfile library
        with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Add dependency files from package directory
            for root, _, files in os.walk(package_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, package_dir))

            # Add Lambda source files (all .py files in the lambda directory)
            for file in os.listdir(lambda_dir):
                if file.endswith(".py"):
                    zipf.write(os.path.join(lambda_dir, file), file)

        # Lambda Function for Handling
        oauth_lambda = lambda_.Function(
            self,
            "OAuthTokenLambda",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="handler.main",
            code=lambda_.Code.from_asset(zip_file_path),
            environment={
                "SECRET_NAME": "OAuthClientCredentials",
            },
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            timeout=Duration.seconds(10),
        )

        # Grant Lambda permission to use KMS key for decryption
        encryption_key.grant_decrypt(oauth_lambda)

        # Grant Lambda permission to read from Secrets Manager
        oauth_secret.grant_read(oauth_lambda)

        # IAM Policy to allow Lambda to access SSM Parameter Store
        ssm_policy = iam.PolicyStatement(
            actions=[
                "ssm:GetParameter",
                "ssm:PutParameter",
            ],
            resources=["arn:aws:ssm:*:*:parameter/oauth/*"],  # Adjust as needed
            effect=iam.Effect.ALLOW,
        )

        # Attach IAM policy to Lambda
        oauth_lambda.add_to_role_policy(ssm_policy)

        # Internal API Gateway
        api = apigateway.RestApi(
            self,
            "InternalAPIGateway",
            rest_api_name="Internal Services API",
            description="Handles internal VPC service API calls",
            endpoint_configuration=apigateway.EndpointConfiguration(
                types=[apigateway.EndpointType.PRIVATE],
            ),
            deploy_options=apigateway.StageOptions(
                logging_level=apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=True,
                metrics_enabled=True,
            ),
        )
        # Create a VPC endpoint for API Gateway
        vpc_endpoint = ec2.InterfaceVpcEndpoint(
            self,
            "ApiGatewayVpcEndpoint",
            vpc=self.vpc,
            service=ec2.InterfaceVpcEndpointAwsService.APIGATEWAY,
        )

        # Secure API Gateway Endpoint
        internal_apis = api.root.add_resource("token")
        internal_apis.add_method(
            "GET", apigateway.LambdaIntegration(oauth_lambda), api_key_required=False
        )

        # Ensures API Gateway deploys AFTER VPC Endpoint
        api.node.add_dependency(vpc_endpoint)

        # Attach resource policy to allow VPC access
        api_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            principals=[iam.AnyPrincipal()],  # Allows access from any principal
            actions=["execute-api:Invoke"],  # Allows API invocation
            resources=[
                # f"{api.arn_for_execute_api()}/*"
                "*"
            ],  # Applies to all resources under API Gateway
            conditions={
                "StringEquals": {
                    # Restrict to specific VPC Endpoint
                    "aws:SourceVpce": vpc_endpoint.vpc_endpoint_id
                }
            },
        )

        api_policy_document = iam.PolicyDocument(statements=[api_policy])
        api.node.default_child.add_property_override("Policy", api_policy_document)

        # Create a private hosted zone
        hosted_zone = route53.PrivateHostedZone(
            self,
            "HostedZone",
            zone_name="internal.abaseen.cloud",
            vpc=self.vpc,  # Associate the hosted zone with your VPC
        )

        # Create a custom domain name and associate it with an SSL certificate
        certificate = acm.Certificate(
            self,
            "Certificate",
            domain_name="api.internal.abaseen.cloud",
            validation=acm.CertificateValidation.from_dns(),
        )

        # Store the certificate ARN in SSM Parameter Store
        ssm.StringParameter(
            self,
            "CertificateArnParameter",
            parameter_name="/certificates/arns/api_internal_abaseen_cloud",
            string_value=certificate.certificate_arn,
        )

        # Create a domain name for the API Gateway and attach the certificate
        domain_name = apigateway.DomainName(
            self,
            "InternalAPIGatewayDomain",
            domain_name="api.internal.abaseen.cloud",
            certificate=certificate,
            endpoint_type=apigateway.EndpointType.REGIONAL,
        )

        # Create a DNS record to point to the API Gateway
        a_record = route53.ARecord(
            self,
            "ApiGatewayAliasRecord",
            zone=hosted_zone,
            target=route53.RecordTarget.from_alias(
                targets53.ApiGatewayDomain(domain_name)
            ),
            record_name="api",
        )

        # Ensure API Gateway is created before Route 53
        a_record.node.add_dependency(domain_name)

        # Map the custom domain name to the API Gateway stage
        apigateway.BasePathMapping(
            self,
            "BasePathMapping",
            domain_name=domain_name,
            rest_api=api,
            stage=api.deployment_stage,
        )

        # Logging for Monitoring
        self.log_group = logs.LogGroup(
            self,
            "OAuthLogGroup",
            log_group_name=f"/aws/lambda/{oauth_lambda.function_name}",
            removal_policy=RemovalPolicy.DESTROY,
            retention=logs.RetentionDays.ONE_WEEK,
        )

        ######

        # Outputs
        CfnOutput(self, "VpcId", value=self.vpc.vpc_id)

        # Add tags to all resources in this stack
        Tags.of(self).add("Project", "Sindhu")
        Tags.of(self).add("Stack", "Sindhu_LZ")
        Tags.of(self).add("Environment", "Development")
        Tags.of(self).add("auto-delete", "never")
