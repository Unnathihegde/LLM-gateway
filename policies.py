import re
import logging
import sys
from typing import List, Dict, Any
from abc import ABC, abstractmethod

import yaml


# ---------------- Logger ----------------

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


logger = get_logger("Policies")


# ---------------- Base Policy ----------------

class PromptPolicy(ABC):
    """Abstract base class for all policy layers in the gateway."""

    def __init__(self, name: str, policy_config: Dict[str, Any]):
        self.name = name
        self.config = policy_config or {}

    @abstractmethod
    def evaluate_prompt(self, text: str) -> Dict[str, Any]:
        raise NotImplementedError


# ---------------- Concrete Policies ----------------

class PII_Scrubber(PromptPolicy):
    """Simple PII scrubber for input prompts (currently masks emails)."""

    def __init__(self, policy_config: Dict[str, Any]):
        super().__init__("PII_Scrubber", policy_config)
        self.email_regex = re.compile(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        )
        self.mask_token = self.config.get("mask_token", "[EMAIL_MASKED]")

    def evaluate_prompt(self, text: str) -> Dict[str, Any]:
        masked = self.email_regex.sub(self.mask_token, text)
        if masked != text:
            return {
                "status": "MASK",
                "details": "PII (email) masked.",
                "processed_prompt": masked,
            }
        return {"status": "PASS", "details": "No PII found."}


class Jailbreak_Detector(PromptPolicy):
    """Detects basic jailbreak / rule override attempts."""

    def __init__(self, policy_config: Dict[str, Any]):
        super().__init__("Jailbreak_Detector", policy_config)
        defaults = [
            "ignore previous rules",
            "dan mode",
            "jailbreak",
            "bypass safety",
            "act as if you are not an ai",
        ]
        self.keywords = [kw.lower() for kw in policy_config.get("keywords", defaults)]

    def evaluate_prompt(self, text: str) -> Dict[str, Any]:
        low = text.lower()
        for kw in self.keywords:
            if kw in low:
                return {"status": "BLOCK", "details": f"Jailbreak detected: '{kw}'"}
        return {"status": "PASS", "details": "No jailbreak detected."}


class Semantic_Threat_Detector(PromptPolicy):
    """
    Detects dangerous intent using regex logic.
    NOW includes strong 'bomb' detection including:
      - make the bomb
      - how to make bomb
      - explosive device
      - IED
      - pipe bomb
    """

    def __init__(self, policy_config: Dict[str, Any]):
        super().__init__("Semantic_Threat_Detector", policy_config)

        # enhanced dangerous patterns
        self.block_patterns: List[re.Pattern] = [
            # ---- Bomb making intent ----
            re.compile(r"\b(make|build|create|manufacture)\s+(a|the)?\s*bomb\b", re.I),
            re.compile(r"\bhow to (make|build|create|manufacture)\s+(a|the)?\s*bomb\b", re.I),
            re.compile(r"\bbomb\s*recipe\b", re.I),
            re.compile(r"\bexplosive\s+device\b", re.I),
            re.compile(r"\bpipe\s*bomb\b", re.I),
            re.compile(r"\bied\b", re.I),

            # ---- General harmful intent ----
            re.compile(r"\bhow to hack a bank\b", re.I),
            re.compile(r"\bhow to (kill|poison)\b", re.I),
        ]

        # rewrite / salvage patterns
        self.rewrite_patterns: List[re.Pattern] = [
            re.compile(r"\b(hack|bypass)\b.*\b(firewall|router|wifi|system)\b", re.I)
        ]

        self.rewrite_template = (
            "This query was rewritten to focus only on defensive cybersecurity. "
            "Explain best practices without attack steps: {prompt}"
        )

    def evaluate_prompt(self, text: str) -> Dict[str, Any]:

        # Special case: verb + bomb (strong safety)
        if re.search(r"\bbomb\b", text, re.I) and re.search(r"(make|build|create|manufacture)", text, re.I):
            return {
                "status": "BLOCK",
                "details": "Dangerous bomb-making intent detected.",
            }

        # block patterns
        for pat in self.block_patterns:
            if pat.search(text):
                return {
                    "status": "BLOCK",
                    "details": f"Semantic threat detected (pattern: '{pat.pattern}')",
                }

        # rewrite patterns
        for pat in self.rewrite_patterns:
            if pat.search(text):
                new = self.rewrite_template.format(prompt=text)
                return {
                    "status": "REWRITE",
                    "details": "Potentially unsafe → rewritten to defensive intent.",
                    "processed_prompt": new,
                }

        return {"status": "PASS", "details": "No semantic threat detected."}


class Output_Sanitizer(PromptPolicy):
    """Sanitizes LLM output (PII masking + disallowed-link filtering)."""

    def __init__(self, policy_config: Dict[str, Any]):
        super().__init__("Output_Sanitizer", policy_config)

        phone = policy_config.get(
            "phone_pattern",
            r"(?:(?:\+?\d{1,3}[-.\s]?)|\(0?\d{3}\)[-.\s]?)?\d{3}[-.\s]?\d{4}(?:[-.\s]?\d{3})?",
        )
        email = policy_config.get(
            "email_pattern",
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        )

        self.phone_regex = re.compile(phone)
        self.email_regex = re.compile(email)

        self.mask_token = policy_config.get("mask_token", "[REDACTED]")
        self.disallowed = policy_config.get(
            "disallowed_domains",
            ["pastebin.com", "anonfiles.com"],
        )

    def evaluate_prompt(self, text: str) -> Dict[str, Any]:
        original = text
        processed = text

        processed = self.phone_regex.sub(self.mask_token, processed)
        processed = self.email_regex.sub(self.mask_token, processed)

        for dom in self.disallowed:
            processed = re.sub(
                rf"https?://{re.escape(dom)}[^\s]*",
                self.mask_token,
                processed,
                flags=re.I,
            )

        if processed != original:
            return {
                "status": "MASK",
                "details": "Output sanitized (PII or unsafe links).",
                "processed_prompt": processed,
            }

        return {"status": "PASS", "details": "Output clean."}


# ---------------- Policy Map ----------------

POLICY_MAP = {
    "PII_Scrubber": PII_Scrubber,
    "Jailbreak_Detector": Jailbreak_Detector,
    "Semantic_Threat_Detector": Semantic_Threat_Detector,
    "Output_Sanitizer": Output_Sanitizer,
}


# ---------------- Config Loader ----------------

def load_policy_configs_from_file(path: str) -> Dict[str, List[Dict[str, Any]]]:
    """Loads policy configurations from a YAML file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        if not cfg or "policies" not in cfg:
            logger.error("YAML must contain a top-level 'policies' dictionary.")
            return {}
        return cfg["policies"]
    except Exception as e:
        logger.error(f"Failed to load YAML: {e}")
        return {}
