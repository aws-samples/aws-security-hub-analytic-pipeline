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

    def __stream_to_s3(self, target_bucket: s3.Bucket, expiration: cdk.Duration, raw_prefix='raw/firehose',
                       destination_prefix='Findings'):
        role = iam.Role(self, 'DeliveryRole',
                        assumed_by=iam.ServicePrincipal('firehose.amazonaws.com'))

        target_bucket.grant_read_write(role)

        target_bucket.add_lifecycle_rule(
            prefix=f'/{raw_prefix}',
            expiration=expiration
        )

        # Transforms Findings so that keys are consumable by Athena
        transform_findings = lambda_python.PythonFunction(self, 'TransformFindings',
                                                          entry=path.join(self.this_dir,
                                                                          '../assets/lambdas/transform_findings'),
                                                          handler='handler',
                                                          runtime=lmb.Runtime.PYTHON_3_8,
                                                          environment={
                                                              'bucket_name': target_bucket.bucket_name,
                                                              'destination_prefix': destination_prefix
                                                          })

        target_bucket.grant_read_write(transform_findings)

        target_bucket.add_object_created_notification(s3_notifications.LambdaDestination(transform_findings))

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
                                      detail_type=['Security Hub Findings - Imported', 'Security Hub Findings - Custom Action'],
                                  ))
        target = events_targets.KinesisFirehoseStream(
            stream=delivery_stream,
        )
        stream_rule.add_target(target)

    def __create_glue_crawler(self, bucket: s3.Bucket, prefix: str):
        role = iam.Role(self, 'CrawlerRole',
                        assumed_by=iam.ServicePrincipal('glue.amazonaws.com'))
        # S3 Permissions
        bucket.grant_read(role)
        role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                's3:GetBucketLocation',
                's3:ListBucket',
                's3:ListAllMyBuckets',
                's3:GetBucketAcl'
            ],
            resources=[f'{bucket.bucket_arn}*']
        ))
        # Glue Permissions
        role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                'glue:*',
                'iam:ListRolePolicies',
                'iam:GetRole',
                'iam:GetRolePolicy'
            ],
            resources=['*']
        ))
        role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                's3:GetObject'
            ],
            resources=[
                'arn:aws:s3:::crawler-public*',
                'arn:aws:s3:::aws-glue-*'
            ]
        ))
        role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents'
            ],
            resources=['arn:aws:logs:*:*:/aws-glue/*']
        ))

        database = glue.Database(self, 'SecurityHubDatabase',
                                 database_name='security_hub_database')

        crawler = glue.CfnCrawler(self, 'SecurityHubCrawler',
                                  role=role.role_arn,
                                  database_name=database.database_name,
                                  schedule=glue.CfnCrawler.ScheduleProperty(
                                      schedule_expression='cron(0 0/1 * * ? *)'
                                  ),
                                  targets=glue.CfnCrawler.TargetsProperty(
                                      s3_targets=[glue.CfnCrawler.S3TargetProperty(
                                          path=f's3://{bucket.bucket_name}/{prefix}'
                                      )]
                                  ),
                                  table_prefix='security-hub-crawled-',
                                  name='SecurityHubCrawler')

    def stream_to_athena(self, target_bucket: s3.Bucket,
                         expiration: cdk.Duration = cdk.Duration.days(5)):
        destination_prefix = 'Findings'
        self.__stream_to_s3(
            target_bucket,
            expiration,
            raw_prefix='raw/firehose',
            destination_prefix=destination_prefix
        )
        self.__create_glue_crawler(
            target_bucket,
            destination_prefix
        )

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
