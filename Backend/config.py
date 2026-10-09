"""Runtime configuration for the SecurBuddy backend."""

import logging
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("securbuddy")

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
DATASET_PATH = PROJECT_ROOT / "golden_dataset.json"

MODEL = "openai/gpt-oss-20b"

HTTP_TIMEOUT_SECONDS = 10.0
# Free-tier quotas: AbuseIPDB allows 1000 checks/day, VirusTotal 4 lookups/min.
MAX_IP_CHECKS = 3
MAX_URL_CHECKS = 2
MAX_INPUT_CHARS = 20_000

SYSTEM_PROMPT = (
    "You are SecurBuddy, an expert cybersecurity assistant. The user pasted a "
    "suspicious log, email, or note and deterministic analysis has already been "
    "run on it. Explain the attack in simple, plain English and give exact, "
    "copy-pasteable remediation commands. Rules: (1) Be concise and practical. "
    "(2) Always give concrete shell commands using a real firewall tool such as "
    "ufw, iptables, or Windows netsh. (3) Never invent indicators of compromise - "
    "only reference IOCs present in the analysis context you are given. (4) When "
    "asked how to clean up or harden a system, give a prioritised checklist. "
    "(5) Say clearly when something is harmless or a false positive."
)


class Settings(BaseSettings):
    """Application settings loaded from the local .env file."""

    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    groq_api_key: str = Field(default="", validation_alias="GROQ_API_KEY")
    abuseipdb_api_key: str = Field(default="", validation_alias="ABUSEIPDB_API_KEY")
    virustotal_api_key: str = Field(default="", validation_alias="VIRUSTOTAL_API_KEY")
    model: str = Field(default=MODEL, validation_alias="SECURBUDDY_MODEL")


settings = Settings()