# wazuh-send-mail
This project contains scripts that process Wazuh alerts and automatically send
them by email. The original implementation is written in Python, but an
optimised C version is also provided.

Features:
- Parsing Wazuh alert logs
- Truncating large logs for better readability
- Sending formatted HTML emails

Python version: 3.12.3

## C version
The `c_version` directory contains a lightweight implementation written in C
using `libcurl` for SMTP. Compile it with:

```bash
cd c_version && make
```

The resulting `send_wazuh_mail` binary reads the alert log, builds an HTML
email and sends it via your SMTP server. A sample systemd unit file is provided
as `wazuh-mail-c.service`.

To test manually you can run:

```bash
./c_version/send_wazuh_mail
```

SMTP settings no longer need to be compiled in. Adjust them in the
configuration file instead.

### Configuration file

The C program reads `wazuh-mail.conf` from `/opt/wazuh-mail` on startup.
A sample configuration file is included in `c_version/wazuh-mail.conf`.
It allows you to configure SMTP parameters and the minimum alert level
that triggers an email notification:

```ini
smtp_server=smtp.example.com
smtp_port=25
email_from=wazuh@example.com
email_to=support@example.com
min_level=9
```

If a setting is missing or cannot be parsed, built-in defaults are used
(server `smtp.example.com`, port `25`, sender `wazuh@example.com`,
recipient `support@example.com`, and alert level `9`).

## Enabling the service

To run the mail notifier automatically, install one of the provided systemd
unit files and enable it:

```bash
# For the Python implementation
sudo ln -s /opt/wazuh-mail/python_version/wazuh-mail.service /etc/systemd/system/wazuh-mail.service
# Or for the C implementation
sudo ln -s /opt/wazuh-mail/c_version/wazuh-mail-c.service /etc/systemd/system/wazuh-mail-c.service

sudo systemctl daemon-reload
sudo systemctl enable wazuh-mail.service    # or wazuh-mail-c.service
sudo systemctl start wazuh-mail.service     # or wazuh-mail-c.service
```

The service expects the program files to be located in `/opt/wazuh-mail` as
referenced in the unit files. Adjust the paths if you deploy the scripts
elsewhere.
