import os
import re
import boto3
import logging
from typing import List
from time import sleep

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class ProwlerListGroups:
    def __init__(self, topic_arn):
        self.topic = boto3.resource('sns').Topic(topic_arn)

    @staticmethod
    def __list_groups():
        stream = os.popen('/prowler/prowler -l -b')
        raw_out = stream.read()
        return raw_out.split('\n')

    @staticmethod
    def process_groups(raw_out: List[str]):
        ret = []

        new_lines = [st.replace('[0;39', '').replace('[0;34m', '').replace('[0;35m', '').replace('[0;36m','') for st in raw_out]

        for n in new_lines:
            if len(n.strip()) > 0:
                start = n.index('[')
                stop = n.index(']')
                ret.append(n[start + 1: stop])

        return ret

    def handler(self, event, context):
        groups = ProwlerListGroups.__list_groups()
        processed = ProwlerListGroups.process_groups(groups)
        logger.info(f'groups found {groups}')
        for p in processed:
            sleep(0.1) # Adds Slight Delay to help with Throttling API Calls during fanout
            self.topic.publish(Message=p)


def handler(event, context):
    ProwlerListGroups(topic_arn=os.environ.get('topic_arn')).handler(event, context)
    return 'Done'
