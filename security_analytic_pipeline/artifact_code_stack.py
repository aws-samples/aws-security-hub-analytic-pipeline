from os import path


from aws_cdk import (
    core as cdk,
    aws_s3 as s3
)

from .prowler_scanner import ProwlerScanner
from .security_hub import SecurityHub


class SecurityAnalyticPipelineStack(cdk.Stack):
    """This stack"""
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        security_hub = SecurityHub(self, 'SecurityHub')
        target_bucket = s3.Bucket(self, 'TargetBucket',
                                  block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                  auto_delete_objects=True,
                                  removal_policy=cdk.RemovalPolicy.DESTROY,
                                  encryption=s3.BucketEncryption.KMS_MANAGED,
                                  )
        security_hub.stream_to_athena(target_bucket)

        scanner = ProwlerScanner(self, 'ExampleScanner')
        security_hub.enable_import_findings_for_product(scanner.security_hub_product_arn)






