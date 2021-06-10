FROM toniblyx/prowler:latest as builder

FROM public.ecr.aws/lambda/python:3.8

COPY --from=builder /prowler /prowler
RUN ln -s /tmp /prowler/output
RUN chmod a+wr /prowler
COPY app.py ./

RUN yum install -y python3 bash curl jq file coreutils which && \
    pip3 install --upgrade pip && \
    pip install awscli boto3 detect-secrets

CMD ["app.handler"]
