import boto3
from botocore.config import Config
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class EnableSecurityHubResource:
    def __init__(self):
        self.region = os.environ.get('AWS_REGION')
        self.client = boto3.client('securityhub')

    def on_create(self, event):
        logger.info('Enabling Security Hub')
        logger.debug('Event: %s' % event)
        try:
            self.client.enable_security_hub(
                EnableDefaultStandards=True
            )
        except self.client.exceptions.ResourceConflictException:
            logger.info('Security Hub already enabled')

        return {'PhysicalResourceId': self.region}

    def on_update(self, event):
        logger.warning(
            'Attempt to update custom resource.  Security Hub is either enabled or disabled.  See Event for details %s' % event)
        return {'PhysicalResourceId': self.region}

    def on_delete(self, event):

        logger.info('Disabling Security Hub')
        logger.debug('Event: %s' % event)
        self.client.disable_security_hub()
        return {'PhysicalResourceId': self.region}

    def handle(self, event, context):
        request_type = event['RequestType']
        props = event["ResourceProperties"]
        region = None
        if 'region' in props and props['region'] is not None:
            self.region = props['region']
            self.client = boto3.client('securityhub', config=Config(
                region_name=self.region
            ))

        if request_type == 'Create':
            return self.on_create(event)
        elif request_type == 'Update':
            return self.on_update(event)
        elif request_type == 'Delete':
            return self.on_delete(event)
        else:
            raise Exception("Invalid request type: %s" % request_type)

fn = EnableSecurityHubResource()

def handler(event, context):
    return fn.handle(event,context)
