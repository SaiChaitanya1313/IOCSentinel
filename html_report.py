from datetime import datetime


def export_html(results, filename=None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ioc_report_{timestamp}.html"

    html = """
    <html>
    <head><title>IOC Report</title></head>
    <body>
    <h2>IOC Threat Report</h2>
    <table border="1">
    <tr>
        <th>IOC</th>
        <th>Type</th>
        <th>Verdict</th>
        <th>Severity</th>
        <th>MITRE</th>
    </tr>
    """

    for row in results:
        html += f"""
        <tr>
            <td>{row['ioc']}</td>
            <td>{row['type']}</td>
            <td>{row['verdict']}</td>
            <td>{row['severity']}</td>
            <td>{row['mitre']}</td>
        </tr>
        """

    html += "</table></body></html>"

    with open(filename, "w") as f:
        f.write(html)

    print(f"✅ HTML report saved to: {filename}")