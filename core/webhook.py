import os
import json
import logging
from typing import Any, Dict

import requests

logger = logging.getLogger("websec_ai")

def send_webhook(payload: Dict[str, Any]) -> bool:
    url = os.environ.get("WEBSECAI_WEBHOOK_URL", "").strip()
    if not url:
        return False
    try:
        r = requests.post(url, json=payload, timeout=10, headers={"Content-Type": "application/json"})
        if r.status_code >= 200 and r.status_code < 300:
            return True
        logger.warning("Webhook %s returned %s", url, r.status_code)
    except Exception as e:
        logger.warning("Webhook failed: %s", e)
    return False

def webhook_scan_complete(scan_result: Dict[str, Any]) -> bool:
    return send_webhook({"event": "scan_complete", "data": scan_result})
