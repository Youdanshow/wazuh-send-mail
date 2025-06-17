#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <curl/curl.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>

#define DEFAULT_SMTP_SERVER "smtp.example.com"
#define DEFAULT_SMTP_PORT 25
#define DEFAULT_EMAIL_FROM "wazuh@example.com"
#define DEFAULT_EMAIL_TO "support@example.com"
#define ALERT_FILE_PATH "/var/ossec/logs/alerts/alerts.log"

#define MAX_LOG_LENGTH 15000
#define CONFIG_FILE "/opt/wazuh-mail/wazuh-mail.conf"

static int min_alert_level = 9;
static char smtp_server[128] = DEFAULT_SMTP_SERVER;
static int smtp_port = DEFAULT_SMTP_PORT;
static char email_from[128] = DEFAULT_EMAIL_FROM;
static char email_to[128] = DEFAULT_EMAIL_TO;

struct upload_status {
    size_t bytes_read;
    size_t len;
    const char *data;
};

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
    if(regex_extract(text, "->([^\\n]+)", info->logfile, sizeof(info->logfile)) != 0)
        strcpy(info->logfile, "Unknown");
    if(regex_extract(text, "([0-9]{4} [A-Z][a-z]{2} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})", info->time, sizeof(info->time)) != 0)
        strcpy(info->time, "Unknown");
    if(regex_extract(text, "Rule: [0-9]+ \\(level ([0-9]+)\\)", info->level, sizeof(info->level)) != 0)
        strcpy(info->level, "Unknown");
    if(regex_extract(text, "Rule: [0-9]+ \\(level [0-9]+\\) -> '([^']*)'", info->rule_desc, sizeof(info->rule_desc)) != 0)
        strcpy(info->rule_desc, "Wazuh Alert");
    snprintf(info->subject, sizeof(info->subject), "[Wazuh] %s", info->rule_desc);
}

/* Build MIME email payload with plain text and HTML */
static char *build_email(const alert_info *info, const char *log, size_t *payload_len)
{
    const char *boundary = "----=_wazuh_mail_boundary";
    char *plain = NULL; char *html = NULL;
    size_t log_len = strlen(log);
    int truncated = 0;
    if(log_len > MAX_LOG_LENGTH) {
        log_len = MAX_LOG_LENGTH;
        truncated = 1;
    }
    plain = malloc(log_len + 64);
    html = malloc(log_len + 512);
    if(!plain || !html) { free(plain); free(html); return NULL; }
    memcpy(plain, log, log_len);
    plain[log_len] = '\0';
    if(truncated)
        strcat(plain, "\n\n[Log automatically truncated for email compatibility]");

    snprintf(html, log_len + 512,
        "<html>\n"
        "<body style=\"font-family:Arial,sans-serif;\">\n"
        "<h2 style=\"color:#e60000;\">Wazuh Alert</h2>\n"
        "<p><strong>Level:</strong> %s<br>\n"
        "<strong>Detail:</strong> <em>%s</em><br>\n"
        "<strong>When:</strong> %s<br>\n"
        "<strong>Hostname:</strong> %s<br>\n"
        "<strong>Log file:</strong> %s</p>\n"
        "<div style=\"background-color:#f9f9f9;padding:10px;border-left:4px solid #e60000;margin-top:10px; max-height:400px; overflow:auto;\">\n"
        "<div style=\"font-family:monospace; white-space:pre-wrap;\">%.*s</div>\n"
        "</div>\n%s"
        "</body></html>\n",
        info->level, info->rule_desc, info->time, info->hostname, info->logfile,
        (int)log_len, log,
        truncated ? "<p style=\"color:#888;margin-top:8px;\"><em>[Log automatically truncated for email compatibility]</em></p>" : "");

    size_t size = strlen(info->subject) + strlen(plain) + strlen(html) + 512;
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
    snprintf(url, sizeof(url), "smtp://%s:%d", smtp_server, smtp_port);
    curl_easy_setopt(curl, CURLOPT_URL, url);
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

