from assets.lambdas.transform_findings.index import TransformFindings
import boto3
from moto import mock_s3


def __make_bucket(bucket_name: str):
    bucket = boto3.resource('s3').Bucket(bucket_name)
    bucket.create()
    return bucket


@mock_s3
def test_fix_dictionary():
    bucket = __make_bucket('tester')
    transform_findings = TransformFindings(bucket.name)

    finding = {
        'first/level/test': 'test',
        'ProductArn': 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
        'Types': ['Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark'],
        'Description': 'Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to port 22.',
        'SchemaVersion': '2018-10-08',
        'Compliance': {'Status': 'PASSED'},
        'GeneratorId': 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/4.1',
        'FirstObservedAt': '2021-01-31T04:52:30.123Z',
        'CreatedAt': '2021-01-31T04:52:30.123Z',
        'RecordState': 'ACTIVE',
        'Title': '4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22',
        'Workflow': {'Status': 'RESOLVED'},
        'LastObservedAt': '2021-05-07T11:05:27.353Z',
        'Severity': {'Normalized': 0, 'Label': 'INFORMATIONAL', 'Product': 0, 'Original': 'INFORMATIONAL'},
        'UpdatedAt': '2021-05-07T11:05:25.775Z',
        'FindingProviderFields': {
            'Types': [
                'Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark'],
            'Severity': {'Normalized': 0, 'Label': 'INFORMATIONAL', 'Product': 0, 'Original': 'INFORMATIONAL'}
        },
        'WorkflowState': 'NEW',
        'ProductFields': {
            'StandardsGuideArn': 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0',
            'StandardsGuideSubscriptionArn': 'arn:aws:securityhub:us-east-1:0123456789:subscription/cis-aws-foundations-benchmark/v/1.2.0',
            'RuleId': '4.1',
            'RecommendationUrl': 'https://docs.aws.amazon.com/console/securityhub/standards-cis-4.1/remediation',
            'RelatedAWSResources:0/name': 'securityhub-restricted-ssh-38a80c22',
            'RelatedAWSResources:0/type': 'AWS::Config::ConfigRule',
            'StandardsControlArn': 'arn:aws:securityhub:us-east-1:0123456789:control/cis-aws-foundations-benchmark/v/1.2.0/4.1',
            'aws/securityhub/ProductName': 'Security Hub',
            'aws/securityhub/CompanyName': 'AWS',
            'aws/securityhub/FindingId': 'arn:aws:securityhub:us-east-1::product/aws/securityhub/arn:aws:securityhub:us-east-1:0123456789:subscription/cis-aws-foundations-benchmark/v/1.2.0/4.1/finding/2a55570b-74e9-4aa3-9f4e-66f515c7ff03'
        },
        'AwsAccountId': '0123456789',
        'Id': 'arn:aws:securityhub:us-east-1:0123456789:subscription/cis-aws-foundations-benchmark/v/1.2.0/4.1/finding/2a55570b-74e9-4aa3-9f4e-66f515c7ff03',
        'Remediation': {
            'Recommendation': {
                'Text': 'For directions on how to fix this issue, please consult the AWS Security Hub CIS documentation.',
                'Url': 'https://docs.aws.amazon.com/console/securityhub/standards-cis-4.1/remediation'}
        },
        'Resources': [{
            'Partition': 'aws',
            'Type': 'AwsEc2SecurityGroup',
            'Details': {
                'AwsEc2SecurityGroup': {
                    'GroupName': 'default',
                    'OwnerId': '0123456789',
                    'VpcId': 'vpc-0123456789',
                    'IpPermissions': [{'IpProtocol': '-1', 'UserIdGroupPairs': [
                        {'UserId': '0123456789', 'GroupId': 'sg-0123456789'}]}],
                    'IpPermissionsEgress': [{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}],
                    'GroupId': 'sg-0123456789'}
            },
            'Region': 'us-east-1', 'Id': 'arn:aws:ec2:us-east-1:0123456789:security-group/sg-0123456789'
        }]
    }
    result = transform_findings.fix_dictionary(finding)

    assert isinstance(result, dict)
    assert 'first/level/test' not in result
    assert 'first_level_test' in result
    assert 'ProductFields' in result
    assert 'aws/securityhub/ProductName' not in result['ProductFields']
    assert 'aws_securityhub_ProductName' in result['ProductFields']
    assert 'aws/securityhub/CompanyName' not in result['ProductFields']
    assert 'aws_securityhub_CompanyName' in result['ProductFields']
    assert 'aws/securityhub/FindingId' not in result['ProductFields']
    assert 'aws_securityhub_FindingId' in result['ProductFields']
    assert 'RelatedAWSResources:0/name' not in result['ProductFields']
    assert 'RelatedAWSResources_0_name' in result['ProductFields']