## AWS Security Hub Analytic Pipeline

[AWS Security Hub](https://aws.amazon.com/security-hub/) is a service that gives you aggregated visibility into your security and compliance posture across multiple AWS accounts. By joining Security Hub with [Amazon QuickSight](https://aws.amazon.com/quicksight/) — a scalable, serverless, embeddable, machine learning-powered business intelligence (BI) service built for the cloud — your senior leaders and decision-makers can consume dashboards to empower data-driven decisions and ensure a secure fleet of AWS resources. In organizations that operate at cloud scale, being able to summarize and perform trending analysis is key to identifying and remediating problems early leading to overall success of the organization. Additionally, QuickSight dashboards can be embedded to provide leaders with single-panes of glass.

This repository contains a CDK stack that builds the following infrastructure

![CDK Infrastructure](blog_post/images/CDK_Portion.png)

Essentially there are two major components:
- A custom CDK Construct for Security Hub that handles the necessary infrastructure to stream findings to Athena
- A custom CDK Construct to scan an account using Prowler.

## Building the stack

Create a virtual environment

```bash
$ python3 -m venv .venv
$ source .venv/bin/activate
```

Install CDK dependencies

```bash
$ pip install -r requirements.txt
```

## Deploy the stack

```bash
$ cdk deploy
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

