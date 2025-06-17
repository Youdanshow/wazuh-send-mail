import smtplib
from email.message import EmailMessage
import re
import logging
from datetime import datetime

# Configuration parameters
SMTP_SERVER = 'smtp.example.com'  # SMTP server address
SMTP_PORT = 25  # SMTP port
EMAIL_FROM = 'wazuh@example.com'  # Sender email address
EMAIL_TO = 'support@example.com'  # Recipient email address
ALERT_FILE_PATH = '/var/ossec/logs/alerts/alerts.log'  # Path to Wazuh alert log file

# Logger configuration
LOG_FILE = '/var/log/wazuh-email.log'
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def parse_wazuh_alert(log_lines):
    """
    Extract relevant data from Wazuh alert log.
    Parses hostname, logfile, time, level, rule description, and constructs email subject.
    """
    full_log = "\n".join(log_lines)

    # Extract hostname from log
    hostname_match = re.search(r'\d{4} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} (\S+)->', full_log)
    if not hostname_match:
        hostname_match = re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2})? (\S+)', full_log)
    hostname = hostname_match.group(1) if hostname_match else "Unknown"

    # Extract log file name
    logfile_match = re.search(r'->([^\s]+)', full_log)
    logfile = logfile_match.group(1) if logfile_match else "Unknown"

    # Extract timestamp
    time_match = re.search(r'(\d{4} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2})', full_log)
    time = time_match.group(1) if time_match else "Unknown"

    # Extract alert level
    level_match = re.search(r'Rule: \d+ \(level (\d+)\)', full_log)
    level = level_match.group(1) if level_match else "Unknown"

    # Extract rule description
    desc_match = re.search(r"Rule: \d+ \(level \d+\) -> '(.*?)'", full_log)
    rule_desc = desc_match.group(1) if desc_match else "Wazuh Alert"

    # Construct email subject
    subject = f"[Wazuh] {rule_desc}"

    return {
        "hostname": hostname,
        "logfile": logfile,
        "time": time,
        "level": level,
        "rule_desc": rule_desc,
        "subject": subject,
        "raw_log": full_log
    }

def create_email(alert_data, from_addr, to_addr):
    """
    Generate the email content from parsed alert data.
    Returns an EmailMessage object with both plain text and HTML versions.
    """
    msg = EmailMessage()
    msg['Subject'] = alert_data['subject']
    msg['From'] = from_addr
    msg['To'] = to_addr

    # Truncate large logs to avoid oversized emails
    MAX_LOG_LENGTH = 15000
    raw_log = alert_data['raw_log']
    cut_index = raw_log.rfind('\n', 0, MAX_LOG_LENGTH)
    short_log = raw_log[:cut_index] if cut_index > 0 else raw_log[:MAX_LOG_LENGTH]
    is_truncated = len(raw_log) > len(short_log)

    # Build HTML email content
    html = f"""
    <html>
    <body style="font-family:Arial,sans-serif;">
        <h2 style="color:#e60000;">Wazuh Alert</h2>
        <p style="font-size:16px;">
            <strong>Level:</strong> {alert_data['level']}<br>
            <strong>Detail:</strong> <em>{alert_data['rule_desc']}</em><br>
            <strong>When:</strong> {alert_data['time']}<br>
            <strong>Hostname:</strong> {alert_data['hostname']}<br>
            <strong>Log file:</strong> {alert_data['logfile']}
        </p>
        <a href="https://wazuh.example.com">Go to Wazuh</a>
        <div style="background-color:#f9f9f9;padding:10px;border-left:4px solid #e60000;margin-top:10px; max-height:400px; overflow:auto;">
            <div style="font-size:13px; font-family:monospace; white-space:pre-wrap; overflow-x:auto; word-break:break-word; line-height:1.4; margin:0;">{short_log}</div>
        </div>
        {f'<p style="color:#888;margin-top:8px;"><em>[Log automatically truncated for email compatibility]</em></p>' if is_truncated else ''}
    </body>
    </html>
    """

    # Add both plain text and HTML versions to the email
    msg.set_content(short_log if not is_truncated else short_log + "\n\n[Log automatically truncated for email compatibility]")
    msg.add_alternative(html, subtype='html')

    return msg

def get_last_alert(filepath, min_level=12):
    """
    Read Wazuh alert log file and yield alerts with level >= min_level.
    Each alert is identified by lines starting with "** Alert".
    """
    try:
        with open(filepath, 'r') as f:
            f.seek(0, 2)  # Move to the end of the file
            buffer = []
            while True:
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if line.startswith("** Alert"):
                    if buffer:
                        joined = "\n".join(buffer)
                        level_match = re.search(r'Rule: \d+ \(level (\d+)\)', joined)
                        if level_match and int(level_match.group(1)) >= min_level:
                            yield buffer
                    buffer = [line]
                else:
                    buffer.append(line)
    except Exception as e:
        logging.error(f"Error in get_last_alert: {e}")
        return

if __name__ == "__main__":
    # Main execution: read alerts, parse, and send emails
    for alert_lines in get_last_alert(ALERT_FILE_PATH, min_level=9):
        alert = parse_wazuh_alert(alert_lines)
        email = create_email(alert, EMAIL_FROM, EMAIL_TO)

        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.send_message(email)
                logging.info(f"Alert sent successfully: {alert['subject']}")
        except Exception as e:
            logging.error(f"Failed to send email: {e}")
