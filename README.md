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

Ensure your SMTP settings in `send_wazuh_mail.c` match your environment.
