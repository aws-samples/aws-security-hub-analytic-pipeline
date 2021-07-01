from aws_cdk import (
    core as cdk,
    custom_resources
)

from datetime import datetime


class SSMStoredParameter(custom_resources.AwsCustomResource):
    def __init__(self, scope: cdk.Construct, construct_id: str, parameter_name: str, region: str):
        super().__init__(scope, construct_id,
                             on_update=custom_resources.AwsSdkCall(
                                 service='SSM',
                                 action='getParameter',
                                 parameters={
                                     'Name': parameter_name
                                 },
                                 region=region,
                                 physical_resource_id=custom_resources.PhysicalResourceId.of(
                                     str(datetime.now().timestamp()))
                             ),
                             policy=custom_resources.AwsCustomResourcePolicy.from_sdk_calls(
                                 resources=custom_resources.AwsCustomResourcePolicy.ANY_RESOURCE
                             )
                         )

    @property
    def value_as_a_string(self) -> str:
        return self.get_response_field_reference('Parameter.Value').to_string()
