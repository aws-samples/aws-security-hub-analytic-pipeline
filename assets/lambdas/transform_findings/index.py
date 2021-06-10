import boto3
import json
import logging
import re
from os import environ
from flatten_json import flatten

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class TransformFindings:
    def __init__(self, bucket_name, destination_prefix='AWSLogs'):
        self.__s3_resource = boto3.resource('s3')
        self.__s3_client = boto3.client('s3')

        self.__bucket_name = bucket_name
        self.__bucket = self.__s3_resource.Bucket(self.__bucket_name)
        self.__destination_prefix = destination_prefix

    def fix_dictionary(self, finding: dict):
        keys = finding.keys()
        ret = {}
        for key in keys:
            new_key = str(key)
            value = finding[key]
            value_as_string = str(value)

            if isinstance(value, dict):
                value = self.fix_dictionary(value)
            if isinstance(key, str):
                new_key = re.sub('\W', '_', key)

            ret[new_key] = value_as_string
        return ret

    def __process_record(self, object_key):
        output = {}
        response = self.__s3_client.get_object(Bucket=self.__bucket_name, Key=object_key)
        raw_findings = '[' + response['Body'].read().decode('utf-8').replace('}{', '},\n{') + ']'
        raw_list = json.loads(raw_findings)
        for item in raw_list:
            account_id = item['detail']['findings'][0]['AwsAccountId']
            sp = item['resources'][0].split('/')
            if 'product/aws/securityhub' in item['resources'][0]:
                product_node = sp[3]
                product = product_node.split(':')
                product_name = product[2]
                region = product[3]
            else:
                product_name = sp[2]
                region = sp[0].split(':')[3]

            key = account_id + '/' + product_name + '/' + region
            findings = item['detail']['findings']
            for f in findings:
                logger.info(f'raw_finding={f}')
                flatten_finding = flatten(f)
                fixed = self.fix_dictionary(flatten_finding)
                logger.info(f'fixed_finding={fixed}')

                if key not in output:
                    output[key] = [fixed]
                else:
                    output[key].append(fixed)

        return output

    def __persist_record(self, output: dict, partition: str, object_name):
        for key in output:
            s3_path = f'{self.__destination_prefix}/{key}/{partition}/{object_name}.json'
            body = ''
            for version in output[key]:
                body += json.dumps(version) + '\n'
            self.__bucket.put_object(Key=s3_path, Body=body)

    def handle(self, event, context):
        records = event['Records']
        for r in records:
            object_key = r['s3']['object']['key']
            output = self.__process_record(object_key)

            partition = '/'.join(object_key.split('/')[2:-2])
            object_name = object_key.split('/')[-1]

            self.__persist_record(output, partition, object_name)


def handler(event, context):
    logger.info(event)
    return TransformFindings(bucket_name=environ['bucket_name'],
                             destination_prefix=environ['destination_prefix']).handle(event, context)
