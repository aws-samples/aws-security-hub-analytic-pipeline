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
        # stream = os.popen(f"/prowler/prowler -c '{check_id}' -b -M json")
        stream = os.popen(f"/prowler/prowler -c '{check_id}' -M 'json-asff' -S")
        raw_out = stream.read()
        print(f'raw_results={raw_out}')
        return raw_out

    @staticmethod
    def process_prowler_results(results: str, disallowed_severities: List[str] = None) -> List[dict]:
        if disallowed_severities is None:
            disallowed_severities = ['Informational']

        lines = results.split('\n')
        results_arr = [json.loads(l) for l in lines if len(l.strip()) > 0]

        return [finding for finding in results_arr if
                finding['Status'] == 'FAIL' and finding['Severity'] not in disallowed_severities]


    def handle(self, event, context):
        records = event['Records']
        for r in records:
            group = r['Sns']['Message']
            raw_output = ProwlerScanGroup.__get_check(group)
            processed = ProwlerScanGroup.process_prowler_results(results=raw_output)
            for p in processed:
                print(p)
                try:
                    self.topic.publish(Message=json.dumps(p))
                except:
                    e = sys.exc_info()[0]
                    print(e)



def handler(event, context):
    ProwlerScanGroup(topic_arn=os.environ['topic_arn']).handle(event, context)
    return 'Done: python'
