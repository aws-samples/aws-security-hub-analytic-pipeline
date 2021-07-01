#!/usr/bin/env python3
import os
from aws_cdk import core as cdk

# For consistency with TypeScript code, `cdk` is the preferred import name for
# the CDK's core module.  The following line also imports it as `core` for use
# with examples from the CDK Developer's Guide, which are in the process of
# being updated to use `cdk`.  You may delete this import if you don't need it.
from aws_cdk import core

from security_analytic_pipeline.scanner_plus_security_hub_stack import ScannerPlusSecurityHubStack
from security_analytic_pipeline.analytic_sink_stack import AnalyticSinkStack

app = core.App()

#  You can get a list of all regions by using these commands
# response = boto3.client('ec2').describe_regions()
# region_names = [r['RegionName'] for r in response['Regions'] if r['OptInStatus'] == 'opt-in-not-required']

analytic_sink_stack = AnalyticSinkStack(app, 'AnalyticSink',
                                        env=cdk.Environment(
                                            region='us-east-1'
                                        ))

regions = ['us-east-2', 'us-west-1']

for r in regions:
    ScannerPlusSecurityHubStack(app, f'ScannerAndSecurityHub-{r}',
                                env=cdk.Environment(
                                    region=r
                                ),
                                sink_region='us-east-1',
                                )

app.synth()
