# wazuh-send-mail

Ce projet fournit deux programmes permettant d'envoyer automatiquement par courriel les alertes générées par Wazuh. Une version en **Python** et une version plus légère en **C** sont disponibles.

## Fonctionnalités communes
- Surveillance du fichier `alerts.log` de Wazuh en temps réel
- Extraction des informations principales (hôte, fichier concerné, niveau, description)
- Envoi d'un courriel en texte et HTML
- Niveau minimum d'alerte configurable via un fichier `.conf`

## Version Python
- Script : `python_version/send_wazuh_mail.py`
- Compatible Python 3.12, sans dépendance externe
- Exemple de configuration : `python_version/wazuh-mail.conf`
- Unité systemd fournie : `python_version/wazuh-mail.service`

Exécution manuelle :
```bash
python3 python_version/send_wazuh_mail.py
```

## Version C
- Code source : `c_version/send_wazuh_mail.c`
- Utilise **libcurl** pour l'envoi SMTP
- Compilation :
```bash
cd c_version && make
```
- Exemple de configuration : `c_version/wazuh-mail.conf`
- Unité systemd : `c_version/wazuh-mail-c.service`

## Fichier de configuration
Les fichiers `wazuh-mail.conf` définissent les paramètres SMTP et le niveau minimal déclenchant l'envoi d'un message :
```ini
smtp_server=smtp.example.com
smtp_port=25
smtp_security=none   # none, starttls ou ssl
email_from=wazuh@example.com
email_to=admin@example.com
min_level=9
```
Copiez ce fichier dans `/opt/wazuh-mail/` pour qu'il soit chargé au démarrage.

## Installation comme service
1. Placez le répertoire du projet dans `/opt/wazuh-mail`
2. Activez l'une des unités systemd fournies :
   - Version Python :
     ```bash
     sudo cp /opt/wazuh-mail/python_version/wazuh-mail.service /etc/systemd/system/wazuh-mail.service
     sudo systemctl daemon-reload
     sudo systemctl enable wazuh-mail.service
     sudo systemctl start wazuh-mail.service
     ```
   - Version C :
     ```bash
     sudo cp /opt/wazuh-mail/c_version/wazuh-mail-c.service /etc/systemd/system/wazuh-mail-c.service
     sudo systemctl daemon-reload
     sudo systemctl enable wazuh-mail-c.service
     sudo systemctl start wazuh-mail-c.service
     ```

Les journaux sont écrits dans `/var/log/wazuh-email.log`. Adaptez les chemins si nécessaire selon votre installation.
