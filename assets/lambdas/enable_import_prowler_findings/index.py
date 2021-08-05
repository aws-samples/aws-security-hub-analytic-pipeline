import boto3
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class EnableSecurityHubResource:
    def __init__(self):
        self.client = boto3.client('securityhub')
        self.region = os.environ.get('AWS_REGION')

    def on_create(self, event):
        logger.debug('Event: %s' % event)
        properties = event['ResourceProperties']
        product_arn = properties['product_arn']
        logger.info('Enabling Security Hub Integration: %s' % product_arn)
        try:
            self.client.enable_import_findings_for_product(
                ProductArn=product_arn
            )
        except self.client.exceptions.ResourceConflictException:
            logger.info('Product already enabled')

        return {'PhysicalResourceId': product_arn}

    def on_update(self, event):
        properties = event['ResourceProperties']
        product_arn = properties['product_arn']
        logger.warning(
            'Attempt to update custom resource.  Products is either enabled or disabled.  See Event for details %s' % event)
        return {'PhysicalResourceId': product_arn}

    def on_delete(self, event):
        logger.debug('Event: %s' % event)
        properties = event['ResourceProperties']
        product_arn = properties['product_arn']
        logger.info('Disabling Security Hub Integration: %s' % product_arn)
        self.client.disable_import_findings_for_product(
            ProductArn=product_arn
        )
        return {'PhysicalResourceId': product_arn}

    def handle(self, event, context):
        request_type = event['RequestType']
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
    return fn.handle(event, context)
