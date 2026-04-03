import httpx
import logging

async def send_slack_webhook(webhook_url: str, target: str, risk_score: int, critical_count: int, medium_count: int, low_count: int, scan_url: str = ""):
    """Sends an elegant Block Kit message to Slack upon scan completion."""
    if not webhook_url:
        return

    color = "#22c55e" if risk_score >= 70 else "#eab308" if risk_score >= 40 else "#ef4444"
    status_text = "Secure" if risk_score >= 70 else "Warning" if risk_score >= 40 else "Critical Risk"

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🛡️ ShieldScan Completed on {target}"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Risk Score:*\n{risk_score}/100 ({status_text})"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Critical Vulnerabilities:*\n{critical_count}"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Medium Vulnerabilities:*\n{medium_count}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Low Vulnerabilities:*\n{low_count}"
                            }
                        ]
                    }
                ]
            }
        ]
    }

    if scan_url:
        payload["attachments"][0]["blocks"].append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"<{scan_url}|View Full Detailed Report here>"
            }
        })

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code != 200:
                logging.error(f"Slack webhook failed: {resp.text}")
    except Exception as e:
        logging.error(f"Slack webhook exception: {e}")
