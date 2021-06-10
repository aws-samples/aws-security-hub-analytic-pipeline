import os
import boto3
from typing import List
import json
import sys

# ./prowler -g 'internet-exposed' -b -M json

class ProwlerScanGroup:
    def __init__(self, topic_arn):
        self.topic = boto3.resource('sns').Topic(topic_arn)

    @staticmethod
    def __get_check(check_id:str) -> str:
        stream = os.popen(f"/prowler/prowler -c '{check_id}' -M 'json-asff' -S")
        raw_out = stream.read()
        return raw_out

    def handle(self, event, context):
        records = event['Records']
        for r in records:
            group = r['Sns']['Message']
            ProwlerScanGroup.__get_check(group)



def handler(event, context):
    ProwlerScanGroup(topic_arn=os.environ['topic_arn']).handle(event, context)
    return 'Done: python'
