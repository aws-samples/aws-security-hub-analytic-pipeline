import boto3
from aws_cdk import (
    core as cdk,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_glue as glue,
    aws_iam as iam,
    aws_lambda as lmb,
    aws_lambda_python as lambda_python,
    aws_logs as logs,
    aws_s3 as s3,
    aws_s3_notifications as s3_notifications,
    aws_kinesisfirehose as kinesisfirehose,
    custom_resources
)

from os import path


class SecurityHub(cdk.Construct):
    """Security Hub Contruct designed to act like an L2 CDK Construct"""

    def __init__(self, scope: cdk.Construct, identifier: str):
        super().__init__(scope, identifier)

        self.this_dir = path.dirname(__file__)

        enable_disable_function = lmb.Function(self, 'EnableSHFunction',
                                               code=lmb.Code.from_asset(path.join(self.this_dir,
                                                                                  '../assets/lambdas/enable_security_hub_resource')),
                                               handler='index.handler',
                                               runtime=lmb.Runtime.PYTHON_3_8)

        enable_disable_function.add_to_role_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                'securityhub:EnableSecurityHub',
                'securityhub:DisableSecurityHub'
            ],
            resources=['*']
        ))

        enable_provider = custom_resources.Provider(self, 'EnableSHProvider',
                                                    on_event_handler=enable_disable_function,
                                                    log_retention=logs.RetentionDays.ONE_DAY)
        cdk.CustomResource(self, 'EnableSH',
                           service_token=enable_provider.service_token,
                           removal_policy=cdk.RemovalPolicy.RETAIN)
        self.__enabled = True

    @property
    def is_enabled(self):
        return self.__enabled

    def stream_raw_findings_to_s3(self,
                                  bucket_name: str,
                                  bucket_arn: str,
                                  bucket_region=None,
                                  raw_prefix='raw/firehose'):
        if bucket_region is None:
            bucket_region = cdk.Aws.REGION

        target_bucket = s3.Bucket.from_bucket_attributes(self, 'TargetBucket',
            bucket_name=bucket_name,
            bucket_arn=bucket_arn,
            region=bucket_region
        )

        role = iam.Role(self, 'DeliveryRole',
                        assumed_by=iam.ServicePrincipal('firehose.amazonaws.com'))

        target_bucket.grant_read_write(role)

        delivery_stream = kinesisfirehose.CfnDeliveryStream(self, 'SHDeliveryStream',
                                                            delivery_stream_type='DirectPut',
                                                            extended_s3_destination_configuration=kinesisfirehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
                                                                role_arn=role.role_arn,
                                                                bucket_arn=target_bucket.bucket_arn,
                                                                buffering_hints=kinesisfirehose.CfnDeliveryStream.BufferingHintsProperty(
                                                                    interval_in_seconds=900,
                                                                    size_in_m_bs=128
                                                                ),
                                                                compression_format='UNCOMPRESSED',
                                                                prefix=raw_prefix
                                                            ))

        stream_rule = events.Rule(self, 'StreamFromKinesisToS3',
                                  event_pattern=events.EventPattern(
                                      source=['aws.securityhub'],
                                      detail_type=['Security Hub Findings - Imported'],
                                  ))
        target = events_targets.KinesisFirehoseStream(
            stream=delivery_stream,
        )
        stream_rule.add_target(target)

    def enable_import_findings_for_product(self, product_arn):
        this_dir = path.dirname(__file__)

        enable_disable_function = lmb.Function(self, 'EnableSHImportFunction',
                                               code=lmb.Code.from_asset(path.join(self.this_dir,
                                                                                  '../assets/lambdas/enable_import_prowler_findings')),
                                               handler='index.handler',
                                               runtime=lmb.Runtime.PYTHON_3_8)

        enable_provider = custom_resources.Provider(self, 'EnableSHImportProvider',
                                                    on_event_handler=enable_disable_function,
                                                    log_retention=logs.RetentionDays.ONE_DAY)

        cdk.CustomResource(self, 'EnableSHImport',
                           service_token=enable_provider.service_token,
                           properties={
                               'product_arn': product_arn
                           },
                           removal_policy=cdk.RemovalPolicy.RETAIN)
