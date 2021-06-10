## AWS Security Hub Analytic Pipeline

[AWS Security Hub](https://aws.amazon.com/security-hub/) is a service that gives you aggregated visibility into your security and compliance posture across multiple AWS accounts. However, by exporting findings to Athena, you can enrich the data up with additional sources such as your configuration management database (CMDB) or IT service management database.  Additionally, you can build analytic dimenions to find trends and patterns.  This code is part of an up coming blog post (link TBA) on exposing Security Hub Findings to Senior Leaders.

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

