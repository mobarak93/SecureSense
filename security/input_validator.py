import re
import logging
import time
from collections import defaultdict
from typing import Dict, List, Any

# Setup logger for security violations
logger = logging.getLogger("security_validator")
logger.setLevel(logging.WARNING)

# Check if handler already exists to prevent duplicate logs
if not logger.handlers:
    handler = logging.FileHandler("security.log", mode="a", encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# -----------------------------------------------------------------------------
# 1. Prompt Injection Defense
# -----------------------------------------------------------------------------
PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "you are now",
    "system prompt",
    "jailbreak",
    "forget your instructions",
    "act as"
]

MAX_INPUT_LENGTH = 2000

def validate_input(user_input: str) -> None:
    """Validates user input against prompt injection patterns and length constraints.
    
    Raises:
        ValueError: If input length exceeds limits or contains injection patterns.
    """
    if len(user_input) > MAX_INPUT_LENGTH:
        msg = f"Input exceeds maximum allowed length of {MAX_INPUT_LENGTH} characters (got {len(user_input)})."
        logger.warning(f"Violation: Input length limit exceeded. Message: {msg}")
        raise ValueError(msg)
        
    lower_input = user_input.lower()
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern in lower_input:
            msg = f"Potential prompt injection pattern detected: '{pattern}'"
            logger.warning(f"Violation: Prompt Injection attempt. Message: {msg}")
            raise ValueError(msg)

# -----------------------------------------------------------------------------
# 2. Output Sanitizer
# -----------------------------------------------------------------------------
# SSN format: XXX-XX-XXXX or XXX XX XXXX
SSN_REGEX = re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")

# Credit card formats: 13 to 16 digits, with optional separators
CREDIT_CARD_REGEX = re.compile(r"\b(?:\d[ -]*?){13,16}\b")

# API Keys, secrets, passwords, tokens patterns
# e.g. api_key="...", password: ..., etc.
API_KEY_REGEX = re.compile(
    r"(?i)\b(api_key|password|secret|token)\b\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{8,}[\"']?",
)

def sanitize_output(output_text: str) -> str:
    """Checks output for accidental exposure of PII or API keys.
    
    Raises:
        ValueError: If sensitive data exposure is detected.
    """
    violation_found = False
    details = []

    # Check for SSN
    if SSN_REGEX.search(output_text):
        violation_found = True
        details.append("SSN exposure detected")

    # Check for Credit Card
    if CREDIT_CARD_REGEX.search(output_text):
        violation_found = True
        details.append("Credit card exposure detected")

    # Check for API Keys / Secrets / Passwords
    if API_KEY_REGEX.search(output_text):
        violation_found = True
        details.append("API key/credential exposure detected")

    if violation_found:
        msg = f"Sensitive data exposure blocked: {', '.join(details)}"
        logger.warning(f"Violation: Output data exposure. Message: {msg}")
        raise ValueError(msg)

    return output_text

# -----------------------------------------------------------------------------
# 3. Rate Limiter
# -----------------------------------------------------------------------------
class SessionRateLimiter:
    def __init__(self, max_queries: int = 10, period: float = 60.0):
        self.max_queries = max_queries
        self.period = period
        self.history = defaultdict(list)

    def check_rate_limit(self, session_id: str) -> None:
        """Checks if session has exceeded the rate limit.
        
        Raises:
            ValueError: If rate limit is exceeded.
        """
        now = time.time()
        # Filter timestamps within the sliding window
        self.history[session_id] = [t for t in self.history[session_id] if now - t < self.period]
        
        if len(self.history[session_id]) >= self.max_queries:
            msg = f"Rate limit exceeded for session '{session_id}'. Maximum {self.max_queries} queries per {self.period}s."
            logger.warning(f"Violation: Rate limit exceeded. Session: {session_id}")
            raise ValueError(msg)
            
        self.history[session_id].append(now)

# Instantiate a global rate limiter for sessions
rate_limiter = SessionRateLimiter()
