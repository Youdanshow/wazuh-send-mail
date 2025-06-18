import smtplib
from email.message import EmailMessage
import re
import logging
import time
import html

# Configuration par défaut
SMTP_SERVER = 'smtp.example.com'
SMTP_PORT = 25
SMTP_SECURITY = 'none'  # none, starttls ou ssl
EMAIL_FROM = 'wazuh@example.com'
EMAIL_TO = 'admin@example.com'
MIN_LEVEL = 9
ALERT_FILE_PATH = '/var/ossec/logs/alerts/alerts.log'
CONFIG_FILE = '/opt/wazuh-mail/wazuh-mail.conf'

# Configuration du logger
LOG_FILE = '/var/log/wazuh-email.log'
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def load_config():
    """Charge les paramètres depuis le fichier de configuration."""
    global SMTP_SERVER, SMTP_PORT, SMTP_SECURITY, EMAIL_FROM, EMAIL_TO, MIN_LEVEL
    try:
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                else:
                    continue

                if key == 'smtp_server':
                    SMTP_SERVER = value
                elif key == 'smtp_port' and value.isdigit():
                    SMTP_PORT = int(value)
                elif key == 'smtp_security':
                    SMTP_SECURITY = value.lower()
                elif key == 'email_from':
                    EMAIL_FROM = value
                elif key == 'email_to':
                    EMAIL_TO = value
                elif key == 'min_level' and value.isdigit():
                    MIN_LEVEL = int(value)
    except FileNotFoundError:
        pass

def parse_wazuh_alert(log_lines):
    """Analyse une alerte Wazuh pour en extraire les données clés."""
    full_log = "\n".join(log_lines)

    hostname_match = re.search(r'\d{4} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} (\S+)->', full_log) or \
                     re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2})? (\S+)', full_log)
    hostname = hostname_match.group(1) if hostname_match else "Inconnu"

    logfile_match = re.search(r'->([^\s]+)', full_log)
    logfile = logfile_match.group(1) if logfile_match else "Inconnu"

    time_match = re.search(r'(\d{4} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2})', full_log)
    time_str = time_match.group(1) if time_match else "Inconnu"

    level_match = re.search(r'Rule: \d+ \(level (\d+)\)', full_log)
    level = level_match.group(1) if level_match else "Inconnu"

    desc_match = re.search(r"Rule: \d+ \(level \d+\) -> '(.*?)'", full_log)
    rule_desc = desc_match.group(1) if desc_match else "Alerte Wazuh"

    subject = f"[Wazuh] {rule_desc}"

    return {
        "hostname": hostname,
        "logfile": logfile,
        "time": time_str,
        "level": level,
        "rule_desc": rule_desc,
        "subject": subject,
        "raw_log": full_log
    }

def create_email(alert_data, from_addr, to_addr):
    """Génère un email HTML avec les données de l’alerte."""
    msg = EmailMessage()
    msg['Subject'] = alert_data['subject']
    msg['From'] = from_addr
    msg['To'] = to_addr

    MAX_LOG_LENGTH = 15000
    raw_log = alert_data['raw_log']
    cut_index = raw_log.rfind('\n', 0, MAX_LOG_LENGTH)
    short_log = raw_log[:cut_index] if cut_index > 0 else raw_log[:MAX_LOG_LENGTH]
    is_truncated = len(raw_log) > len(short_log)

    html_body = f"""
    <html>
    <body style="font-family:Arial,sans-serif;">
        <h2 style="color:#e60000;">Alerte Wazuh</h2>
        <p style="font-size:16px;">
            <strong>Niveau :</strong> {alert_data['level']}<br>
            <strong>Détail :</strong> <em>{html.escape(alert_data['rule_desc'])}</em><br>
            <strong>Quand :</strong> {html.escape(alert_data['time'])}<br>
            <strong>Hostname :</strong> {html.escape(alert_data['hostname'])}<br>
            <strong>Fichier log :</strong> {html.escape(alert_data['logfile'])}
        </p>
        <div style="background-color:#f9f9f9;padding:10px;border-left:4px solid #e60000;margin-top:10px; max-height:400px; overflow:auto;">
            <pre style="font-size:13px; font-family:monospace; white-space:pre-wrap;">{html.escape(short_log)}</pre>
        </div>
        {f'<p style="color:#888;margin-top:8px;"><em>[Log tronqué automatiquement]</em></p>' if is_truncated else ''}
    </body>
    </html>
    """

    msg.set_content(short_log)
    msg.add_alternative(html_body, subtype='html')
    return msg

def get_last_alert(filepath, min_level=12, sleep_time=1.0):
    """Lit les dernières alertes dans le fichier de log."""
    try:
        with open(filepath, 'r') as f:
            f.seek(0, 2)
            buffer = []
            while True:
                line = f.readline()
                if not line:
                    time.sleep(sleep_time)
                    continue
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
        logging.error(f"Erreur dans get_last_alert : {e}")

if __name__ == "__main__":
    load_config()
    for alert_lines in get_last_alert(ALERT_FILE_PATH, min_level=MIN_LEVEL):
        alert = parse_wazuh_alert(alert_lines)
        email = create_email(alert, EMAIL_FROM, EMAIL_TO)
        try:
            if SMTP_SECURITY == 'ssl':
                server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT)
            else:
                server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
                if SMTP_SECURITY == 'starttls':
                    server.starttls()
            with server:
                server.send_message(email)
                logging.info(f"Alerte envoyée avec succès : {alert['subject']}")
        except Exception as e:
            logging.error(f"Échec de l'envoi de l'email : {e}")
