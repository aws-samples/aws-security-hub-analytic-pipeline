import os
import boto3
from typing import List
import json
import sys
import os

class ProwlerScanGroup:
    def __init__(self, topic_arn):
        self.__topic = boto3.resource('sns').Topic(topic_arn)
        self.__region = os.environ['AWS_REGION']

    def __get_check(self, check_id:str) -> str:
        stream = os.popen(f"/prowler/prowler -r {self.__region} -c '{check_id}' -M 'json-asff' -S")
        raw_out = stream.read()
        return raw_out

    def handle(self, event, context):
        records = event['Records']
        for r in records:
            group = r['Sns']['Message']
            self.__get_check(group)



def handler(event, context):
    ProwlerScanGroup(topic_arn=os.environ['topic_arn']).handle(event, context)
    return 'Done: python'
