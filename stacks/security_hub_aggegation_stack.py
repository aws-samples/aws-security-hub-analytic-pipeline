from os import path
from aws_cdk import (
    core as cdk
)

from custom_constructs.security_hub import SecurityHub
from custom_constructs.prowler_scanner import ProwlerScanner
from custom_constructs.ssm_stored_parameter import SSMStoredParameter


class SecurityHubAggregationStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str, sink_region: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        security_hub = SecurityHub(self, 'SecurityHub')
        scanner = ProwlerScanner(self, 'ExampleScanner')

        sink_bucket_name = SSMStoredParameter(self, 'BucketName',
                                              parameter_name='/AnalyticSinkStack/BucketName',
                                              region=sink_region).value_as_a_string
        sink_bucket_arn = SSMStoredParameter(self, 'BucketArn',
                                             parameter_name='/AnalyticSinkStack/BucketArn',
                                             region=sink_region).value_as_a_string

        security_hub.enable_import_findings_for_product(scanner.security_hub_product_arn)
        security_hub.stream_raw_findings_to_s3(
            bucket_name=sink_bucket_name,
            bucket_arn=sink_bucket_arn,
            bucket_region=sink_region
        )
        security_hub.enable_aggregation()
