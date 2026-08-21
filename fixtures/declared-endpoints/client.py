"""Fixture client: endpoint hosts bound at runtime from the environment."""

import os

INFERENCE = f"https://{os.environ['INFERENCE_HOST']}/v2/complete"
MODEL_URL = os.getenv("MODEL_URL", "http://models.internal:8080/v1")
LOG_LEVEL = os.getenv("LOG_LEVEL", "info")
