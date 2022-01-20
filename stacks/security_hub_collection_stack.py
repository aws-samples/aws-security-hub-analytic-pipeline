from os import path
from aws_cdk import (
    core as cdk
)

from custom_constructs.security_hub import SecurityHub
from custom_constructs.prowler_scanner import ProwlerScanner
from custom_constructs.ssm_stored_parameter import SSMStoredParameter


class SecurityHubCollectionStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        security_hub = SecurityHub(self, 'SecurityHub')
        scanner = ProwlerScanner(self, 'ExampleScanner')
        security_hub.enable_import_findings_for_product(scanner.security_hub_product_arn)
