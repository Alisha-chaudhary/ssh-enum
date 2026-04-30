import json
from datetime import datetime

class AlertingSystem:
    def generate_alert(self, alert_data):
        alert = {
            "timestamp": datetime.now().isoformat(),
            "alert": alert_data,
        }
        print(f"[ALERT] {json.dumps(alert, indent=2)}")
        return alert
