import logging
from typing import List, Dict, Any, Optional
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from policies import (
    get_logger,
    POLICY_MAP,
    load_policy_configs_from_file,
)

logger = get_logger("Backend")

CONFIG_PATH = "config.yaml"
POLICY_CONFIG_DATA: Dict[str, List[Dict[str, Any]]] = load_policy_configs_from_file(
    CONFIG_PATH
)

if not POLICY_CONFIG_DATA:
    logger.error("Failed to load policy configurations. Exiting.")
    raise SystemExit(1)


# ==============================
# Core Gateway
# ==============================

class LLM_Safety_Gateway:
    """
    - Loads a named policy chain from YAML config.
    - Applies each policy in sequence.
    - BLOCK is terminal.
    - MASK/REWRITE modifies the text for the next policy.
    """

    def __init__(self, policy_name: str, policy_config_data: Dict[str, List[Dict[str, Any]]]):
        self.policy_name = policy_name
        self.policy_chain = self._load_policies(policy_config_data)

    def _load_policies(self, policy_config_data):
        config_list = policy_config_data.get(self.policy_name)
        if not config_list:
            raise ValueError(f"Policy set '{self.policy_name}' not found in configuration.")

        policy_chain = []
        for item in config_list:
            policy_type = item.get("type")
            policy_config = item.get("config", {})

            policy_cls = POLICY_MAP.get(policy_type)
            if not policy_cls:
                logger.warning("Unknown policy type '%s' skipped.", policy_type)
                continue

            instance = policy_cls(policy_config)
            policy_chain.append(instance)
            logger.info("Loaded policy: %s", instance.name)

        if not policy_chain:
            raise ValueError(f"No valid policies loaded for policy set '{self.policy_name}'.")

        return policy_chain

    def process_prompt(self, text: str) -> Dict[str, Any]:
        current_text = text
        audit_log = []
        final_status = "PASS"

        for policy in self.policy_chain:
            result = policy.evaluate_prompt(current_text)
            status = result.get("status", "PASS")
            details = result.get("details", "")

            audit_log.append({
                "policy": policy.name,
                "status": status,
                "details": details
            })

            if status == "BLOCK":
                return {
                    "status": "BLOCK",
                    "original_text": text,
                    "processed_text": None,
                    "audit_log": audit_log,
                    "final_reason": details,
                }

            if status in ("MASK", "REWRITE"):
                processed = result.get("processed_prompt")
                if processed:
                    current_text = processed
                final_status = status

        return {
            "status": final_status,
            "original_text": text,
            "processed_text": current_text,
            "audit_log": audit_log,
            "final_reason": "Policy chain executed successfully.",
        }


# ==============================
# API Models
# ==============================

class GatewayRequest(BaseModel):
    text: str
    policy_name: str = "Enterprise_input"


class GatewayResponse(BaseModel):
    status: str
    original_text: str
    processed_text: Optional[str]
    audit_log: List[Dict[str, Any]]
    final_reason: str
    gateway_time_ms: float
    llm_time_ms: Optional[float] = None


class CustomPolicyRequest(BaseModel):
    text: str
    keywords: List[str]


# ==============================
# FastAPI App
# ==============================

app = FastAPI(title="LLM Safety Gateway API")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/policies")
async def list_policies():
    return list(POLICY_CONFIG_DATA.keys())


@app.post("/process_text", response_model=GatewayResponse)
async def process_text_endpoint(request: GatewayRequest):
    if request.policy_name not in POLICY_CONFIG_DATA:
        raise HTTPException(
            status_code=400,
            detail=f"Policy set '{request.policy_name}' not found."
        )

    try:
        gateway = LLM_Safety_Gateway(
            policy_name=request.policy_name,
            policy_config_data=POLICY_CONFIG_DATA
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Policy initialization error: {e}"
        )

    start = time.perf_counter()
    result = gateway.process_prompt(request.text)
    end = time.perf_counter()

    result["gateway_time_ms"] = (end - start) * 1000
    result["llm_time_ms"] = 0.0

    return GatewayResponse(**result)


# ==============================
# Custom Keyword Firewall
# ==============================

class Keyword_Blocker:
    def __init__(self, keywords: List[str]):
        k = [x.strip().lower() for x in keywords if x.strip()]
        self.name = "Keyword_Blocker"
        self.keywords = k

    def evaluate_prompt(self, text: str):
        t = text.lower()
        for kw in self.keywords:
            if kw in t:
                return {
                    "status": "BLOCK",
                    "details": f"Matched custom keyword: '{kw}'"
                }
        return {"status": "PASS", "details": "No keyword match."}


@app.post("/process_text_custom", response_model=GatewayResponse)
async def process_text_custom(request: CustomPolicyRequest):
    blocker = Keyword_Blocker(request.keywords)

    start = time.perf_counter()
    result = blocker.evaluate_prompt(request.text)
    end = time.perf_counter()

    blocked = (result["status"] == "BLOCK")
    processed = None if blocked else request.text

    return GatewayResponse(
        status=result["status"],
        original_text=request.text,
        processed_text=processed,
        audit_log=[{
            "policy": "Keyword_Blocker",
            "status": result["status"],
            "details": result["details"],
        }],
        final_reason=result["details"],
        gateway_time_ms=(end - start) * 1000,
        llm_time_ms=0.0,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend:app", host="127.0.0.1", port=8000, reload=True)
