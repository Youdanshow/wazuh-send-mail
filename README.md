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

- Clonner le projet
   ```bash
   git clone https://github.com/Youdanshow/wazuh-send-mail/
   ```
- Setup
   ```bash
   sudo mkdir /opt/wazuh-mail
   cd /wazuh-send-mail/python_version
   cp * /opt/wazuh-mail
   cp wazuh-mail.service /etc/systemd/system/
   ```
   
- Création d’un utilisateur `wazuh-mail`
   ```bash
   useradd --system --no-create-home --shell /usr/sbin/nologin wazuh-mail
   usermod -aG wazuh wazuh-mail
   ```

Exécution manuelle :
```bash
python3 python_version/send_wazuh_mail.py
```

## Version C
- Code source : `c_version/send_wazuh_mail.c`
- Utilise **libcurl** pour l'envoi SMTP
- Clonner le projet
   ```bash
   git clone https://github.com/Youdanshow/wazuh-send-mail/
   ```
- Compilation
   ```bash
   sudo mkdir /opt/wazuh-mail-c
   cd /wazuh-send-mail/c_version
   cp * /opt/wazuh-mail-c
   cp wazuh-mail-c.service /etc/systemd/system/
   sudo make
   ```
- Création d’un utilisateur `wazuh-mail`
   ```bash
   useradd --system --no-create-home --shell /usr/sbin/nologin wazuh-mail
   usermod -aG wazuh wazuh-mail
   ```

Exécution manuelle :
```bash
./send
```

- Fichier de configuation : `wazuh-mail.conf`
- Unité systemd : `/etc/systemd/system/wazuh-mail-c.service`

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

## Installation comme service (Python)
1. Placez le répertoire du projet dans `/opt/wazuh-mail`
2. Activez l'une des unités systemd fournies :
   - Version Python :
     ```bash
     sudo systemctl daemon-reload
     sudo systemctl enable wazuh-mail.service
     sudo systemctl start wazuh-mail.service
     ```
## Installation comme service (C)
1. Placez le répertoire du projet dans `/opt/wazuh-mail-c`
2. Activez l'une des unités systemd fournies :
   - Version C :
     ```bash
     sudo systemctl daemon-reload
     sudo systemctl enable wazuh-mail-c.service
     sudo systemctl start wazuh-mail-c.service
     ```

Les journaux sont écrits dans `/var/log/wazuh-email.log`. Adaptez les chemins si nécessaire selon votre installation.
