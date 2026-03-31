import boto3
import json
import logging

client = boto3.client("bedrock-runtime", region_name="us-east-2")


class BedrockResponseError(Exception):
    pass


def invoke(prompt, system_prompt):
    """
    Invoke Claude Haiku 4.5 via Bedrock.

    Args:
        prompt:        User message content (str).
        system_prompt: System prompt content (str).

    Returns:
        Raw text response from the model (str).

    Raises:
        BedrockResponseError on malformed or missing response body.
    """
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 1000,
        "system": system_prompt,
        "messages": [{"role": "user", "content": prompt}],
    })

    try:
        response = client.invoke_model(
            modelId="anthropic.claude-haiku-4-5",
            body=body,
        )
        parsed = json.loads(response["body"].read())
        return parsed["content"][0]["text"]
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        logging.error(f"Bedrock response malformed: {e} | raw response keys: {list(response.keys()) if 'response' in dir() else 'N/A'}")
        raise BedrockResponseError(str(e)) from e
