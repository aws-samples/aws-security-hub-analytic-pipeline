from os import path
from aws_cdk import (
    core as cdk,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_iam as iam,
    aws_lambda as lmb,
    aws_logs as logs,
    aws_sns as sns,
    aws_sns_subscriptions as sns_subscriptions,
    aws_sqs as sqs,
    custom_resources
)
from .security_hub import SecurityHub

MAXIMUM_LAMBDA_TIME = cdk.Duration.minutes(15)


class ProwlerScanner(cdk.Construct):
    """This is a Scanner"""

    def __init__(self, scope: cdk.Construct, identifier: str,
                 schedule: events.Schedule = events.Schedule.rate(cdk.Duration.hours(1))
                 ):
        super().__init__(scope, identifier)
        self.__this_dir = path.dirname(__file__)

        fanout_topic = sns.Topic(self, 'ProwlerFanoutTopic')

        list_checks = self.__create_list_function(fanout_topic)

        events.Rule(self, 'ProwlerScannerSchedule',
                    description='This Rule triggers Prowler to scan at the rate specified in the schedule',
                    schedule=schedule,
                    targets=[events_targets.LambdaFunction(handler=list_checks)])

        scanner = self.__create_scanner_function(fanout_topic)

        queue = sqs.Queue(self, 'ProwlerDeadLetter')

        fanout_topic.add_subscription(
            subscription=sns_subscriptions.LambdaSubscription(
                fn=scanner,
                dead_letter_queue=queue
            )
        )



    @property
    def security_hub_product_arn(self):
        return f'arn:aws:securityhub:{cdk.Aws.REGION}::product/prowler/prowler'

    def __create_list_function(self, fanout_topic: sns.Topic):
        ret = lmb.DockerImageFunction(self, 'ProwlerListChecks',
                                      code=lmb.DockerImageCode.from_image_asset(
                                          path.join(self.__this_dir, '../assets/containers/prowler_list_check')),
                                      environment={
                                          'topic_arn': fanout_topic.topic_arn
                                      },
                                      timeout=MAXIMUM_LAMBDA_TIME)

        fanout_topic.grant_publish(ret)
        return ret

    def __create_scanner_function(self, fanout_topic: sns.Topic):
        ret = lmb.DockerImageFunction(self, 'ProwlerScan',
                                      code=lmb.DockerImageCode.from_image_asset(
                                          path.join(self.__this_dir, '../assets/containers/prowler_scan_check')
                                      ),
                                      environment={
                                          'topic_arn': fanout_topic.topic_arn
                                      },
                                      timeout=MAXIMUM_LAMBDA_TIME)

        fanout_topic.grant_publish(ret)

        ret.add_to_role_policy(iam.PolicyStatement(
            actions=[
                'securityhub:BatchImportFindings',
                'securityhub:GetFindings',
                'dax:ListTables',
                'ds:ListAuthorizedApplications',
                'ds:DescribeRoles',
                'ec2:GetEbsEncryptionByDefault',
                'ecr:Describe*',
                'support:Describe*',
                'tag:GetTagKeys',
                'glue:Get*',
                'glue:SearchTables',
                'glue:BatchGetDevEndpoints',
            ],
            resources=['*'],
            effect=iam.Effect.ALLOW
        ))

        ret.role.add_managed_policy(
            iam.ManagedPolicy.from_managed_policy_arn(self, 'ViewOnlyPolicy',
                                                      managed_policy_arn='arn:aws:iam::aws:policy/job-function/ViewOnlyAccess'
                                                      )
        )

        ret.role.add_managed_policy(
            iam.ManagedPolicy.from_managed_policy_arn(self, 'SecurityAuditPolicy',
                                                      managed_policy_arn='arn:aws:iam::aws:policy/SecurityAudit'
                                                      )
        )
        return ret
