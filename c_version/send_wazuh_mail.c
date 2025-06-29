#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <curl/curl.h>
#include <strings.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>

#define DEFAULT_SMTP_SERVER "smtp.example.com"
#define DEFAULT_SMTP_PORT 25
#define DEFAULT_EMAIL_FROM "wazuh@example.com"
#define DEFAULT_EMAIL_TO "admin@example.com"
#define ALERT_FILE_PATH "/var/ossec/logs/alerts/alerts.log"

#define MAX_LOG_LENGTH 15000
#define CONFIG_FILE "/opt/wazuh-mail/wazuh-mail.conf"

static int min_alert_level = 9;
static char smtp_server[128] = DEFAULT_SMTP_SERVER;
static int smtp_port = DEFAULT_SMTP_PORT;
static char email_from[128] = DEFAULT_EMAIL_FROM;
static char email_to[128] = DEFAULT_EMAIL_TO;

typedef enum { SMTP_SEC_NONE, SMTP_SEC_SSL, SMTP_SEC_STARTTLS } smtp_sec_t;
static smtp_sec_t smtp_security = SMTP_SEC_NONE;

struct upload_status {
    size_t bytes_read;
    size_t len;
    const char *data;
};

/* Convert LF line endings to CRLF as required by SMTP */
static char *normalize_newlines(const char *text)
{
    size_t len = strlen(text);
    size_t extra = 0;
    for(size_t i = 0; i < len; ++i) {
        if(text[i] == '\n')
            extra++;
    }
    char *out = malloc(len + extra + 1);
    if(!out)
        return NULL;
    char *p = out;
    for(size_t i = 0; i < len; ++i) {
        if(text[i] == '\n') {
            *p++ = '\r';
            *p++ = '\n';
        } else {
            *p++ = text[i];
        }
    }
    *p = '\0';
    return out;
}

/* Load configuration from CONFIG_FILE */
static void load_config(void)
{
    FILE *f = fopen(CONFIG_FILE, "r");
    if(!f) return; /* use default */

    char line[256];
    while(fgets(line, sizeof(line), f)) {
        char *p = line;
        while(isspace((unsigned char)*p)) p++;
        if(*p == '#' || *p == '\0')
            continue;
        char *eq = strchr(p, '=');
        if(!eq) continue;
        *eq++ = '\0';
        char *key = p;
        char *value = eq;
        while(*value && isspace((unsigned char)*value)) value++;
        key[strcspn(key, " \t\r\n")] = '\0';
        value[strcspn(value, "\r\n")] = '\0';

        if(strcmp(key, "min_level") == 0) {
            int lvl = atoi(value);
            if(lvl > 0)
                min_alert_level = lvl;
        } else if(strcmp(key, "smtp_server") == 0) {
            strncpy(smtp_server, value, sizeof(smtp_server) - 1);
            smtp_server[sizeof(smtp_server)-1] = '\0';
        } else if(strcmp(key, "smtp_port") == 0) {
            int port = atoi(value);
            if(port > 0)
                smtp_port = port;
        } else if(strcmp(key, "smtp_security") == 0) {
            if(strcasecmp(value, "ssl") == 0)
                smtp_security = SMTP_SEC_SSL;
            else if(strcasecmp(value, "starttls") == 0)
                smtp_security = SMTP_SEC_STARTTLS;
            else
                smtp_security = SMTP_SEC_NONE;
        } else if(strcmp(key, "email_from") == 0) {
            strncpy(email_from, value, sizeof(email_from) - 1);
            email_from[sizeof(email_from)-1] = '\0';
        } else if(strcmp(key, "email_to") == 0) {
            strncpy(email_to, value, sizeof(email_to) - 1);
            email_to[sizeof(email_to)-1] = '\0';
        } else if(isdigit((unsigned char)*key)) {
            int lvl = atoi(key);
            if(lvl > 0)
                min_alert_level = lvl;
        }
    }
    fclose(f);
}

/* Extract first capture group using regex */
static int regex_extract(const char *text, const char *pattern, char *out, size_t outlen)
{
    regex_t reg;
    if(regcomp(&reg, pattern, REG_EXTENDED) != 0)
        return -1;
    regmatch_t m[2];
    int rc = regexec(&reg, text, 2, m, 0);
    if(rc == 0 && m[1].rm_so != -1) {
        size_t len = m[1].rm_eo - m[1].rm_so;
        if(len >= outlen) len = outlen - 1;
        strncpy(out, text + m[1].rm_so, len);
        out[len] = '\0';
        regfree(&reg);
        return 0;
    }
    regfree(&reg);
    return -1;
}

/* Parse alert text and fill fields */
typedef struct {
    char hostname[128];
    char logfile[128];
    char time[128];
    char level[16];
    char rule_desc[256];
    char subject[300];
} alert_info;

static void parse_alert(const char *text, alert_info *info)
{
    if(regex_extract(text, "[0-9]{4} [A-Z][a-z]{2} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} ([^ ]+)->", info->hostname, sizeof(info->hostname)) != 0)
        regex_extract(text, "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[+-][0-9]{2}:[0-9]{2})? ([^ ]+)", info->hostname, sizeof(info->hostname));
    if(regex_extract(text, "->([^\\n]+?)\\s+Rule:", info->logfile, sizeof(info->logfile)) != 0)
        strcpy(info->logfile, "Unknown");
    if(regex_extract(text, "([0-9]{4} [A-Z][a-z]{2} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})", info->time, sizeof(info->time)) != 0)
        strcpy(info->time, "Unknown");
    if(regex_extract(text, "Rule: [0-9]+ \\(level ([0-9]+)\\)", info->level, sizeof(info->level)) != 0)
        strcpy(info->level, "Unknown");
    if(regex_extract(text, "Rule: [0-9]+ \\(level [0-9]+\\) -> '([^']*)'", info->rule_desc, sizeof(info->rule_desc)) != 0)
        strcpy(info->rule_desc, "Wazuh Alert");
    snprintf(info->subject, sizeof(info->subject), "[Wazuh] %s", info->rule_desc);
    for(char *p = info->subject; *p; ++p)
        if(*p == '\r' || *p == '\n') *p = ' ';
}

/* Build MIME email payload with plain text and HTML */
static char *base64_encode(const unsigned char *data, size_t len)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out_len = ((len + 2) / 3) * 4;
    char *out = malloc(out_len + 1);
    if(!out) return NULL;
    char *p = out;
    for(size_t i = 0; i < len; i += 3) {
        unsigned int n = data[i] << 16;
        if(i + 1 < len) n |= data[i+1] << 8;
        if(i + 2 < len) n |= data[i+2];
        *p++ = table[(n >> 18) & 63];
        *p++ = table[(n >> 12) & 63];
        *p++ = (i + 1 < len) ? table[(n >> 6) & 63] : '=';
        *p++ = (i + 2 < len) ? table[n & 63] : '=';
    }
    *p = '\0';
    return out;
}

/* Escape &, <, >, ' and " for safe HTML output */
static char *html_escape(const char *text)
{
    size_t len = 0;
    for(const char *p = text; *p; ++p) {
        switch(*p) {
            case '&': len += 5; break;      /* &amp; */
            case '<':
            case '>': len += 4; break;      /* &lt; &gt; */
            case '"': len += 6; break;      /* &quot; */
            case '\'': len += 5; break;    /* &#39; */
            default: len++; break;
        }
    }
    char *out = malloc(len + 1);
    if(!out) return NULL;
    char *o = out;
    for(const char *p = text; *p; ++p) {
        switch(*p) {
            case '&': memcpy(o, "&amp;", 5); o += 5; break;
            case '<': memcpy(o, "&lt;", 4); o += 4; break;
            case '>': memcpy(o, "&gt;", 4); o += 4; break;
            case '"': memcpy(o, "&quot;", 6); o += 6; break;
            case '\'': memcpy(o, "&#39;", 5); o += 5; break;
            default: *o++ = *p; break;
        }
    }
    *o = '\0';
    return out;
}

static char *load_file_base64(const char *path)
{
    FILE *f = fopen(path, "rb");
    if(!f) return NULL;
    if(fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long len = ftell(f);
    if(len < 0) { fclose(f); return NULL; }
    rewind(f);
    unsigned char *buf = malloc(len);
    if(!buf) { fclose(f); return NULL; }
    if(fread(buf, 1, len, f) != (size_t)len) { free(buf); fclose(f); return NULL; }
    fclose(f);
    char *b64 = base64_encode(buf, len);
    free(buf);
    return b64;
}

static char *build_email(const alert_info *info, const char *log, size_t *payload_len)
{
    const char *boundary = "----=_wazuh_mail_boundary";
    char *plain = NULL;
    char *html = NULL;
    size_t log_len = strlen(log);
    int truncated = 0;
    if(log_len > MAX_LOG_LENGTH) {
        log_len = MAX_LOG_LENGTH;
        truncated = 1;
    }

    char *log_copy = malloc(log_len + 1);
    if(!log_copy) return NULL;
    memcpy(log_copy, log, log_len);
    log_copy[log_len] = '\0';

    char *normalized = normalize_newlines(log_copy);
    if(!normalized) { free(log_copy); return NULL; }

    char *hostname_e = html_escape(info->hostname);
    char *logfile_e = html_escape(info->logfile);
    char *time_e = html_escape(info->time);
    char *rule_e = html_escape(info->rule_desc);
    char *log_html = html_escape(log_copy);
    if(!hostname_e || !logfile_e || !time_e || !rule_e || !log_html) {
        free(log_copy); free(normalized);
        free(hostname_e); free(logfile_e); free(time_e); free(rule_e); free(log_html);
        return NULL;
    }

    size_t plain_extra = truncated ? strlen("\r\n\r\n[Log potentiellement tronqué automatiquement pour compatibilité email]") : 0;
    plain = malloc(strlen(normalized) + plain_extra + 1);
    size_t html_sz = snprintf(NULL, 0,
        "<html>\n"
        "<body style=\"font-family:Arial,sans-serif;\">\n"
        "    <h2 style=\"color:#e60000;\">Alerte Wazuh</h2>\n"
        "    <p style=\"font-size:16px;\">\n"
        "        <strong>Niveau :</strong> %s<br>\n"
        "        <strong>Détail :</strong> <em>%s</em><br>\n"
        "        <strong>Quand :</strong> %s<br>\n"
        "        <strong>Hostname :</strong> %s<br>\n"
        "        <strong>Fichier log :</strong> %s\n"
        "    </p>\n"
        "    <div style=\"background-color:#f9f9f9;padding:10px;border-left:4px solid #e60000;margin-top:10px; max-height:400px; overflow:auto;\">\n"
        "        <div style=\"font-size:13px; font-family:monospace; white-space:pre-wrap; overflow-x:auto; word-break:break-word; line-height:1.4; margin:0;\">%.*s</div>\n"
        "    </div>\n"
        "    <p style=\"color:#888;margin-top:8px;\"><em>Log potentiellement tronqu\xC3\xA9 automatiquement pour compatibilit\xC3\xA9 email</em></p>\n"
        "</body>\n"
        "</html>\n",
        info->level, rule_e, time_e, hostname_e, logfile_e,
        (int)log_len, log_html) + 1;
    
    html = malloc(html_sz);
    if(!plain || !html) { free(log_copy); free(normalized); free(plain); free(html); return NULL; }
    strcpy(plain, normalized);
    if(truncated)
        strcat(plain, "\r\n\r\n[Log potentiellement tronqué automatiquement pour compatibilité email]");

    snprintf(html, html_sz,
        "<html>\n"
        "<body style=\"font-family:Arial,sans-serif;\">\n"
        "    <h2 style=\"color:#e60000;\">Alerte Wazuh</h2>\n"
        "    <p style=\"font-size:16px;\">\n"
        "        <strong>Niveau :</strong> %s<br>\n"
        "        <strong>Détail :</strong> <em>%s</em><br>\n"
        "        <strong>Quand :</strong> %s<br>\n"
        "        <strong>Hostname :</strong> %s<br>\n"
        "        <strong>Fichier log :</strong> %s\n"
        "    </p>\n"
        "    <div style=\"background-color:#f9f9f9;padding:10px;border-left:4px solid #e60000;margin-top:10px; max-height:400px; overflow:auto;\">\n"
        "        <div style=\"font-size:13px; font-family:monospace; white-space:pre-wrap; overflow-x:auto; word-break:break-word; line-height:1.4; margin:0;\">%.*s</div>\n"
        "    </div>\n"
        "    <p style=\"color:#888;margin-top:8px;\"><em>Log potentiellement tronqu\xC3\xA9 automatiquement pour compatibilit\xC3\xA9 email</em></p>\n"
        "</body>\n"
        "</html>\n",
        info->level, rule_e, time_e, hostname_e, logfile_e,
        (int)log_len, log_html);

    free(log_copy);
    free(normalized);
    free(hostname_e); free(logfile_e); free(time_e); free(rule_e); free(log_html);

    int needed = snprintf(NULL, 0,
             "From: %s\r\n"
             "To: %s\r\n"
             "Subject: %s\r\n"
             "MIME-Version: 1.0\r\n"
             "Content-Type: multipart/alternative; boundary=%s\r\n"
             "\r\n"
             "--%s\r\n"
             "Content-Type: text/plain; charset=utf-8\r\n\r\n"
             "%s\r\n"
             "--%s\r\n"
             "Content-Type: text/html; charset=utf-8\r\n\r\n"
             "%s\r\n"
             "--%s--\r\n",
             email_from, email_to, info->subject, boundary,
             boundary, plain,
             boundary, html,
             boundary);
    if(needed < 0) { free(plain); free(html); return NULL; }
    size_t size = (size_t)needed + 1;
    char *payload = malloc(size);
    if(!payload) { free(plain); free(html); return NULL; }

    snprintf(payload, size,
             "From: %s\r\n"
             "To: %s\r\n"
             "Subject: %s\r\n"
             "MIME-Version: 1.0\r\n"
             "Content-Type: multipart/alternative; boundary=%s\r\n"
             "\r\n"
             "--%s\r\n"
             "Content-Type: text/plain; charset=utf-8\r\n\r\n"
             "%s\r\n"
             "--%s\r\n"
             "Content-Type: text/html; charset=utf-8\r\n\r\n"
             "%s\r\n"
             "--%s--\r\n",
             email_from, email_to, info->subject, boundary,
             boundary, plain,
             boundary, html,
             boundary);

    *payload_len = strlen(payload);
    free(plain); free(html);
    return payload;
}

static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
{
    struct upload_status *upload = (struct upload_status *)userp;

    size_t buffer_size = size * nmemb;
    if(upload->bytes_read >= upload->len)
        return 0;

    size_t copy_len = upload->len - upload->bytes_read;
    if(copy_len > buffer_size)
        copy_len = buffer_size;
    memcpy(ptr, upload->data + upload->bytes_read, copy_len);
    upload->bytes_read += copy_len;
    return copy_len;
}

static int send_email_payload(const char *payload, size_t payload_len)
{
    CURL *curl = curl_easy_init();
    if(!curl) return -1;
    CURLcode res = CURLE_OK;
    char url[256];
    if(smtp_security == SMTP_SEC_SSL)
        snprintf(url, sizeof(url), "smtps://%s:%d", smtp_server, smtp_port);
    else
        snprintf(url, sizeof(url), "smtp://%s:%d", smtp_server, smtp_port);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    if(smtp_security == SMTP_SEC_STARTTLS)
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    char from[160];
    snprintf(from, sizeof(from), "<%s>", email_from);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from);

    struct curl_slist *recipients = NULL;
    char to[160];
    snprintf(to, sizeof(to), "<%s>", email_to);
    recipients = curl_slist_append(recipients, to);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    struct upload_status upload_ctx = {0, payload_len, payload};
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    res = curl_easy_perform(curl);

    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
    return (res == CURLE_OK) ? 0 : -1;
}

static int process_alert(const char *alert)
{
    alert_info info = {0};
    parse_alert(alert, &info);
    int level = atoi(info.level);
    if(level < min_alert_level)
        return 0; /* ignore low level */

    size_t payload_len = 0;
    char *payload = build_email(&info, alert, &payload_len);
    if(!payload) return -1;

    int rc = send_email_payload(payload, payload_len);
    free(payload);
    return rc;
}

int main(void)
{
    load_config();

    FILE *f = fopen(ALERT_FILE_PATH, "r");
    if(!f) {
        fprintf(stderr, "Failed to open %s\n", ALERT_FILE_PATH);
        return 1;
    }

    /* Start watching from the end of the file */
    fseek(f, 0, SEEK_END);

    char *alert = NULL;
    size_t alert_len = 0;
    char line[4096];

    while(1) {
        if(fgets(line, sizeof(line), f)) {
            if(strncmp(line, "** Alert", 8) == 0) {
                if(alert) {
                    process_alert(alert);
                    free(alert);
                    alert = NULL;
                    alert_len = 0;
                }
            }
            size_t l = strlen(line);
            alert = realloc(alert, alert_len + l + 1);
            if(!alert) {
                fprintf(stderr, "Memory allocation failed\n");
                break;
            }
            memcpy(alert + alert_len, line, l);
            alert_len += l;
            alert[alert_len] = '\0';
        } else if(feof(f)) {
            /* Handle log rotation */
            struct stat st, cur;
            static ino_t last_inode = 0;
            if(last_inode == 0 && stat(ALERT_FILE_PATH, &st) == 0)
                last_inode = st.st_ino;
            if(stat(ALERT_FILE_PATH, &cur) == 0 && cur.st_ino != last_inode) {
                fclose(f);
                f = fopen(ALERT_FILE_PATH, "r");
                if(!f) {
                    sleep(1);
                    continue;
                }
                last_inode = cur.st_ino;
                fseek(f, 0, SEEK_END);
                clearerr(f);
                continue;
            }
            clearerr(f);
            sleep(1);
        } else {
            /* Read error */
            break;
        }
    }

    if(alert)
        process_alert(alert);
    free(alert);
    fclose(f);
    return 0;
}

