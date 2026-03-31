FROM public.ecr.aws/lambda/python:3.11

# Install dependencies into the Lambda task root
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY handler.py        .
COPY main.py           .
COPY agent.py          .
COPY bedrock_client.py .
COPY s3_utils.py       .
COPY rules.py          .
COPY tools.py          .
COPY playbooks.py      .

# logs.py is dev-only — not included in the production image

CMD ["handler.lambda_handler"]