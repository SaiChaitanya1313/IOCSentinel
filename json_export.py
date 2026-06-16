import json
from datetime import datetime


def export_json(results, filename=None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ioc_report_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"✅ JSON report saved to: {filename}")