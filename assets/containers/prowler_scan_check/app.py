import os
import boto3
from typing import List
import json
import sys
import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class ProwlerScanGroup:
    def __init__(self, topic_arn):
        self.__topic = boto3.resource('sns').Topic(topic_arn)
        self.__region = os.environ['AWS_REGION']
        logger.debug(f'topic_arn={topic_arn}')
        logger.debug(f'region={self.__region}')

    def __get_check(self, check_id:str) -> str:
        logger.debug('Executing ' + f"/prowler/prowler -r {self.__region} -c '{check_id}' -M 'json-asff' -S")
        stream = os.popen(f"/prowler/prowler -r {self.__region} -f {self.__region} -c '{check_id}' -M 'json-asff' -S")
        raw_out = stream.read()
        return raw_out

    def handle(self, event, context):
        logger.debug(event)
        records = event['Records']
        for r in records:
            group = r['Sns']['Message']
            logger.debug(self.__get_check(group))


def handler(event, context):
    ProwlerScanGroup(topic_arn=os.environ['topic_arn']).handle(event, context)
    return 'Done: python'
