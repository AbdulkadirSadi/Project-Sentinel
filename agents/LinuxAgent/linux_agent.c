#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <pwd.h>
/* Phase 5: TLS mTLS */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

/* Sertifika yollari - install_service.sh tarafindan /etc/sentinel/certs/ altina kopyalanir */
#define CERT_CA     "/etc/sentinel/certs/ca.crt"
#define CERT_CLIENT "/etc/sentinel/certs/agent-client.crt"
#define CERT_KEYF   "/etc/sentinel/certs/agent-client.key"


#define SERVER_IP   "192.168.146.1"
#define SERVER_PORT 8080
#define SECRET_KEY  "EDR_SUPER_SECRET_KEY"
#define MAX_HISTORY     2048
#define MAX_NET_HISTORY 2048

char global_agent_id[128] = {0};
pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;
int current_sock = -1;

/* ── TLS globals (Phase 5) ────────────────────────────────────────────────── */
static SSL_CTX *g_ssl_ctx = NULL;
static SSL     *g_ssl     = NULL;
static int      g_tls_ok  = 0;  /* 1=TLS aktif, 0=plain TCP */

static void init_tls_ctx(void) {
    OPENSSL_init_ssl(0, NULL);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { fprintf(stderr, "[TLS] SSL_CTX_new basarisiz\n"); return; }
    if (SSL_CTX_load_verify_locations(ctx, CERT_CA, NULL) != 1) {
        fprintf(stderr, "[TLS] CA sertifikasi yuklenemedi: %s\n", CERT_CA);
        SSL_CTX_free(ctx); return;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_use_certificate_file(ctx, CERT_CLIENT, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "[TLS] Client cert yuklenemedi: %s\n", CERT_CLIENT);
        SSL_CTX_free(ctx); return;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, CERT_KEYF, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "[TLS] Client key yuklenemedi: %s\n", CERT_KEYF);
        SSL_CTX_free(ctx); return;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "[TLS] Key-cert eslesmedi\n");
        SSL_CTX_free(ctx); return;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    g_ssl_ctx = ctx;
    printf("[TLS] SSL context hazir (mTLS etkin)\n");
}

static int tls_connect_wrap(int sockfd) {
    if (!g_ssl_ctx) { g_tls_ok = 0; return 0; }
    if (g_ssl) { SSL_shutdown(g_ssl); SSL_free(g_ssl); g_ssl = NULL; }
    g_ssl = SSL_new(g_ssl_ctx);
    if (!g_ssl) { g_tls_ok = 0; return -1; }
    SSL_set_fd(g_ssl, sockfd);
    if (SSL_connect(g_ssl) != 1) {
        unsigned long e = ERR_get_error();
        fprintf(stderr, "[TLS] Handshake basarisiz: %s\n", ERR_error_string(e, NULL));
        SSL_free(g_ssl); g_ssl = NULL; g_tls_ok = 0; return -1;
    }
    g_tls_ok = 1;
    X509 *peer = SSL_get_peer_certificate(g_ssl);
    if (peer) { X509_free(peer); }
    printf("[TLS] TLS 1.3 baglantisi kuruldu\n");
    return 0;
}

/* send() yerine: TLS aktifse SSL_write, degilse plain send */
static ssize_t tls_write(const void *buf, size_t len) {
    if (g_tls_ok && g_ssl) return SSL_write(g_ssl, buf, (int)len);
    return send(current_sock, buf, len, 0);
}

/* read() yerine: TLS aktifse SSL_read, degilse plain read */
static int tls_read(int sockfd, void *buf, size_t len) {
    if (g_tls_ok && g_ssl) return SSL_read(g_ssl, buf, (int)len);
    return (int)read(sockfd, buf, len);
}


int previous_pids[MAX_HISTORY];
int previous_pid_count = 0;

typedef struct {
    char local_ip[INET_ADDRSTRLEN];
    int  local_port;
    char remote_ip[INET_ADDRSTRLEN];
    int  remote_port;
    int  pid;
} NetConn;

NetConn previous_nets[MAX_NET_HISTORY];
int previous_net_count = 0;

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static long long get_ts(void) {
    return (long long)time(NULL);
}

void GetAgentID(void) {
    FILE *f = fopen("/etc/machine-id", "r");
    if (f) {
        fgets(global_agent_id, sizeof(global_agent_id), f);
        global_agent_id[strcspn(global_agent_id, "\n")] = 0;
        fclose(f);
    } else {
        strcpy(global_agent_id, "UNKNOWN-LINUX-UUID");
    }
}

void safe_encrypt_send(int soc, const char *message) {
    pthread_mutex_lock(&send_mutex);
    int len = (int)strlen(message);
    char *enc = malloc(len + 1);
    if (!enc) { pthread_mutex_unlock(&send_mutex); return; }
    strcpy(enc, message);
    int key_len = (int)strlen(SECRET_KEY);
    for (int i = 0; i < len; i++) enc[i] ^= SECRET_KEY[i % key_len];

    char *hex = malloc(len * 2 + 2);
    if (!hex) { free(enc); pthread_mutex_unlock(&send_mutex); return; }
    for (int i = 0; i < len; i++) sprintf(hex + (i * 2), "%02X", (unsigned char)enc[i]);
    hex[len * 2]     = '\n';
    hex[len * 2 + 1] = '\0';

    /* Phase 5: TLS veya plain send */
    tls_write(hex, strlen(hex));
    free(enc); free(hex);
    pthread_mutex_unlock(&send_mutex);
}

void decrypt_command(char *hex_str, char *out_plain) {
    int len     = (int)strlen(hex_str);
    int key_len = (int)strlen(SECRET_KEY);
    int j = 0;
    for (int i = 0; i < len; i += 2) {
        char byte_str[3] = { hex_str[i], hex_str[i + 1], '\0' };
        unsigned char byte = (unsigned char)strtol(byte_str, NULL, 16);
        out_plain[j] = byte ^ SECRET_KEY[j % key_len];
        j++;
    }
    out_plain[j] = '\0';
}

void escape_json_string(const char *input, char *output) {
    int j = 0;
    for (int i = 0; input[i]; i++) {
        if      (input[i] == '"'  || input[i] == '\\') { output[j++] = '\\'; output[j++] = input[i]; }
        else if (input[i] == '\n')                      { output[j++] = '\\'; output[j++] = 'n'; }
        else if (input[i] == '\r')                      { /* yoksay */ }
        else if ((unsigned char)input[i] < 0x20)        { /* kontrol karakteri yoksay */ }
        else                                            { output[j++] = input[i]; }
    }
    output[j] = '\0';
}

/* ── ACTION:: Komut İşleyici ─────────────────────────────────────────────── */

static void handle_action(int soc, const char *action_str) {
    char action[64] = {0};
    char result_msg[512] = {0};
    long long ts = get_ts();

    sscanf(action_str, "%63s", action);

    if (strncmp(action, "kill_process", 12) == 0) {
        int pid = 0;
        sscanf(action_str + 12, " pid=%d", &pid);
        if (pid > 0) {
            if (kill((pid_t)pid, SIGKILL) == 0)
                snprintf(result_msg, sizeof(result_msg),
                    "{\"agent_id\":\"%s\",\"os\":\"linux\",\"type\":\"shell_result\","
                    "\"ts\":%lld,\"output\":\"[ACTION] kill_process: PID %d sonlandırıldı\"}",
                    global_agent_id, ts, pid);
            else
                snprintf(result_msg, sizeof(result_msg),
                    "{\"agent_id\":\"%s\",\"os\":\"linux\",\"type\":\"shell_result\","
                    "\"ts\":%lld,\"output\":\"[ACTION] kill_process HATA: PID %d\"}",
                    global_agent_id, ts, pid);
        }

    } else if (strncmp(action, "block_ip", 8) == 0 ||
               strncmp(action, "isolate_network", 15) == 0) {
        char ip[64] = {0};
        char *eq = strchr(action_str, '=');
        if (eq) strncpy(ip, eq + 1, sizeof(ip) - 1);
        if (strlen(ip) > 0) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd),
                "iptables -I OUTPUT -d %s -j DROP 2>/dev/null;"
                "iptables -I INPUT  -s %s -j DROP 2>/dev/null", ip, ip);
            system(cmd);
            snprintf(result_msg, sizeof(result_msg),
                "{\"agent_id\":\"%s\",\"os\":\"linux\",\"type\":\"shell_result\","
                "\"ts\":%lld,\"output\":\"[ACTION] IP engellendi: %s\"}",
                global_agent_id, ts, ip);
        }

    } else if (strncmp(action, "unblock_ip", 10) == 0) {
        char ip[64] = {0};
        char *eq = strchr(action_str, '=');
        if (eq) strncpy(ip, eq + 1, sizeof(ip) - 1);
        if (strlen(ip) > 0) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd),
                "iptables -D OUTPUT -d %s -j DROP 2>/dev/null;"
                "iptables -D INPUT  -s %s -j DROP 2>/dev/null", ip, ip);
            system(cmd);
            snprintf(result_msg, sizeof(result_msg),
                "{\"agent_id\":\"%s\",\"os\":\"linux\",\"type\":\"shell_result\","
                "\"ts\":%lld,\"output\":\"[ACTION] IP engeli kaldırıldı: %s\"}",
                global_agent_id, ts, ip);
        }

    } else if (strncmp(action, "quarantine_file", 15) == 0) {
        char path[512] = {0};
        char *eq = strchr(action_str, '=');
        if (eq) strncpy(path, eq + 1, sizeof(path) - 1);
        if (strlen(path) > 0) {
            char qdir[] = "/var/sentinel/quarantine";
            char qpath[600];
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "mkdir -p %s", qdir);
            system(cmd);
            snprintf(qpath, sizeof(qpath), "%s/%lld", qdir, ts);
            if (rename(path, qpath) == 0)
                snprintf(result_msg, sizeof(result_msg),
                    "{\"agent_id\":\"%s\",\"os\":\"linux\",\"type\":\"shell_result\","
                    "\"ts\":%lld,\"output\":\"[ACTION] Karantinaya alındı: %s -> %s\"}",
                    global_agent_id, ts, path, qpath);
            else
                snprintf(result_msg, sizeof(result_msg),
                    "{\"agent_id\":\"%s\",\"os\":\"linux\",\"type\":\"shell_result\","
                    "\"ts\":%lld,\"output\":\"[ACTION] quarantine_file HATA: %s\"}",
                    global_agent_id, ts, path);
        }
    }

    if (strlen(result_msg) > 0)
        safe_encrypt_send(soc, result_msg);
}


static void parse_hex_ip(const char *hex, char *out) {
    unsigned int ip;
    sscanf(hex, "%X", &ip);
    snprintf(out, INET_ADDRSTRLEN, "%u.%u.%u.%u",
             ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

/* Process sahibinin kullanıcı adını uid'den çek */
static void get_username_by_uid(int uid, char *out, int maxlen) {
    struct passwd *pw = getpwuid((uid_t)uid);
    if (pw) strncpy(out, pw->pw_name, maxlen - 1);
    else    snprintf(out, maxlen, "%d", uid);
    out[maxlen - 1] = '\0';
}

/* /proc/PID/status'tan UID okur */
static int get_process_uid(int pid) {
    char path[64]; char line[256]; int uid = -1;
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line + 4, "%d", &uid);
            break;
        }
    }
    fclose(f);
    return uid;
}

/* ── CPU ─────────────────────────────────────────────────────────────────── */

static double GetCPUPercent(void) {
    static unsigned long long prev_idle = 0, prev_total = 0;
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return 0.0;
    unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
    fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
           &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal);
    fclose(f);
    unsigned long long idle_total = idle + iowait;
    unsigned long long total      = user + nice + system + idle_total + irq + softirq + steal;
    unsigned long long diff_total = total - prev_total;
    unsigned long long diff_idle  = idle_total - prev_idle;
    double percent = (diff_total > 0) ? 100.0 * (double)(diff_total - diff_idle) / (double)diff_total : 0.0;
    prev_idle  = idle_total;
    prev_total = total;
    return percent;
}

/* ── ShellThread ─────────────────────────────────────────────────────────── */

void *ShellThread(void *arg) {
    int soc = *(int *)arg;
    char recvbuf[4096];
    while (1) {
        memset(recvbuf, 0, sizeof(recvbuf));
        int valread = tls_read(soc, recvbuf, 4095);
        if (valread <= 0) break;

        recvbuf[strcspn(recvbuf, "\r\n")] = 0;
        char plain_cmd[512] = {0};
        decrypt_command(recvbuf, plain_cmd);

        long long ts = get_ts();

        /* ACTION:: komutlarını shell'e vermeden işle */
        if (strncmp(plain_cmd, "ACTION::", 8) == 0) {
            handle_action(soc, plain_cmd + 8);
            continue;
        }

        if (strncmp(plain_cmd, "cd ", 3) == 0) {
            plain_cmd[strcspn(plain_cmd, "\n")] = 0;
            chdir(plain_cmd + 3);
            char msg[512];
            snprintf(msg, sizeof(msg),
                "{\"agent_id\":\"%s\",\"os\":\"linux\",\"type\":\"shell_result\","
                "\"ts\":%lld,\"output\":\"Dizin degistirildi.\"}",
                global_agent_id, ts);
            safe_encrypt_send(soc, msg);
            continue;
        }


        char full_cmd[550];
        snprintf(full_cmd, sizeof(full_cmd), "%s 2>&1", plain_cmd);
        FILE *fp = popen(full_cmd, "r");
        if (fp) {
            char line[2048] = {0};
            char total_output[8192] = {0};
            while (fgets(line, sizeof(line), fp) != NULL) {
                if (strlen(total_output) + strlen(line) < 8000)
                    strcat(total_output, line);
            }
            pclose(fp);
            char escaped[16384] = {0};
            escape_json_string(total_output, escaped);

            int req = snprintf(NULL, 0,
                "{\"agent_id\":\"%s\",\"os\":\"linux\",\"type\":\"shell_result\","
                "\"ts\":%lld,\"output\":\"%s\"}",
                global_agent_id, ts, escaped);
            char *msg = malloc(req + 1);
            if (msg) {
                snprintf(msg, req + 1,
                    "{\"agent_id\":\"%s\",\"os\":\"linux\",\"type\":\"shell_result\","
                    "\"ts\":%lld,\"output\":\"%s\"}",
                    global_agent_id, ts, escaped);
                safe_encrypt_send(soc, msg);
                free(msg);
            }
        }
    }
    return NULL;
}

/* ── MetricsThread ───────────────────────────────────────────────────────── */

void *MetricsThread(void *arg) {
    int soc = *(int *)arg;
    char line[256];
    GetCPUPercent(); /* baseline */
    sleep(1);
    while (1) {
        long mem_total = 0, mem_free = 0, mem_buffers = 0, mem_cached = 0;
        FILE *meminfo = fopen("/proc/meminfo", "r");
        if (meminfo) {
            while (fgets(line, sizeof(line), meminfo)) {
                if      (strncmp(line, "MemTotal:",   9) == 0) sscanf(line, "MemTotal: %ld kB",   &mem_total);
                else if (strncmp(line, "MemFree:",    8) == 0) sscanf(line, "MemFree: %ld kB",    &mem_free);
                else if (strncmp(line, "Buffers:",    8) == 0) sscanf(line, "Buffers: %ld kB",    &mem_buffers);
                else if (strncmp(line, "Cached:",     7) == 0) sscanf(line, "Cached: %ld kB",     &mem_cached);
            }
            fclose(meminfo);
        }
        /* gerçek kullanım = total - free - buffers - cached */
        long mem_used = mem_total - mem_free - mem_buffers - mem_cached;
        long ram_percent = mem_total > 0 ? (mem_used * 100) / mem_total : 0;

        double cpu = GetCPUPercent();
        long long ts = get_ts();

        char msg[512];
        snprintf(msg, sizeof(msg),
            "{\"agent_id\":\"%s\",\"os\":\"linux\",\"type\":\"metrics\","
            "\"ts\":%lld,\"cpu_percent\":%.2f,"
            "\"ram_total_kb\":%ld,\"ram_used_kb\":%ld,\"ram_percent\":%ld}",
            global_agent_id, ts, cpu, mem_total, mem_used, ram_percent);
        safe_encrypt_send(soc, msg);
        sleep(5);
    }
    return NULL;
}

/* ── ProcessThread ───────────────────────────────────────────────────────── */

void *ProcessThread(void *arg) {
    int soc = *(int *)arg;
    int initialized = 0;
    while (1) {
        DIR *dir = opendir("/proc");
        if (dir) {
            struct dirent *ent;
            int current_pids[MAX_HISTORY];
            int current_pid_count = 0;

            while ((ent = readdir(dir)) != NULL) {
                if (!isdigit(*ent->d_name)) continue;
                int pid = atoi(ent->d_name);
                if (current_pid_count < MAX_HISTORY) current_pids[current_pid_count++] = pid;

                int is_new = 1;
                for (int i = 0; i < previous_pid_count; i++) {
                    if (previous_pids[i] == pid) { is_new = 0; break; }
                }
                if (!is_new || !initialized) continue;

                /* /proc/PID/stat → name, ppid */
                char stat_path[64];
                snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
                FILE *f = fopen(stat_path, "r");
                if (!f) continue;
                char pname[256] = {0}; int ppid = 0;
                fscanf(f, "%*d (%[^)]) %*c %d", pname, &ppid);
                fclose(f);

                /* /proc/PID/cmdline → tam komut satırı */
                char cmdline[512] = {0};
                char cl_path[64];
                snprintf(cl_path, sizeof(cl_path), "/proc/%d/cmdline", pid);
                FILE *fc = fopen(cl_path, "r");
                if (fc) {
                    int n = (int)fread(cmdline, 1, sizeof(cmdline) - 1, fc);
                    fclose(fc);
                    for (int k = 0; k < n - 1; k++)
                        if (cmdline[k] == '\0') cmdline[k] = ' ';
                }

                /* /proc/PID/exe → çalıştırılabilir dosya yolu */
                char exe_path[512] = {0};
                char exe_link[64];
                snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
                ssize_t r = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
                if (r > 0) exe_path[r] = '\0';

                /* Kullanıcı adı */
                char username[64] = {0};
                int uid = get_process_uid(pid);
                if (uid >= 0) get_username_by_uid(uid, username, sizeof(username));
                else strcpy(username, "unknown");

                /* JSON escape */
                char esc_cmdline[1024] = {0};
                char esc_exe[1024]     = {0};
                char esc_name[512]     = {0};
                escape_json_string(cmdline,  esc_cmdline);
                escape_json_string(exe_path, esc_exe);
                escape_json_string(pname,    esc_name);

                long long ts = get_ts();
                char msg[2048];
                snprintf(msg, sizeof(msg),
                    "{\"agent_id\":\"%s\",\"os\":\"linux\",\"type\":\"process_new\","
                    "\"ts\":%lld,\"pname\":\"%s\",\"pid\":%d,\"ppid\":%d,"
                    "\"cmdline\":\"%s\",\"exe_path\":\"%s\",\"username\":\"%s\"}",
                    global_agent_id, ts, esc_name, pid, ppid,
                    esc_cmdline, esc_exe, username);
                safe_encrypt_send(soc, msg);
            }
            closedir(dir);
            memcpy(previous_pids, current_pids, sizeof(int) * current_pid_count);
            previous_pid_count = current_pid_count;
            initialized = 1;
        }
        sleep(3);
    }
    return NULL;
}

/* ── NetworkThread (/proc/net/tcp) ──────────────────────────────────────── */

void *NetworkThread(void *arg) {
    int soc = *(int *)arg;
    int initialized = 0;
    while (1) {
        NetConn current_nets[MAX_NET_HISTORY];
        int current_net_count = 0;

        /* /proc/net/tcp (IPv4 TCP) */
        FILE *f = fopen("/proc/net/tcp", "r");
        if (f) {
            char line[512];
            fgets(line, sizeof(line), f); /* başlık satırını atla */
            while (fgets(line, sizeof(line), f) && current_net_count < MAX_NET_HISTORY) {
                char local_hex[16], remote_hex[16];
                int  local_port_hex, remote_port_hex, state, uid, inode;
                int  local_ip_hex, remote_ip_hex;
                /* sl: local_address rem_address st ... uid ... inode */
                if (sscanf(line,
                    " %*d: %8[0-9A-Fa-f]:%4x %8[0-9A-Fa-f]:%4x %2x "
                    "%*s %*s %*s %*s %d %*d %d",
                    local_hex, &local_port_hex,
                    remote_hex, &remote_port_hex,
                    &state, &uid, &inode) != 7) continue;

                /* 0x0A = TCP_ESTABLISHED */
                if (state != 0x0A) continue;

                NetConn *nc = &current_nets[current_net_count];
                parse_hex_ip(local_hex,  nc->local_ip);
                parse_hex_ip(remote_hex, nc->remote_ip);
                nc->local_port  = local_port_hex;
                nc->remote_port = remote_port_hex;
                nc->pid         = -1; /* inode → pid eşleme aşağıda */

                /* inode'dan PID bul (/proc/PID/fd/* symlink'leri tara) */
                if (inode > 0) {
                    char inode_str[32];
                    snprintf(inode_str, sizeof(inode_str), "socket:[%d]", inode);
                    DIR *pd = opendir("/proc");
                    if (pd) {
                        struct dirent *pe;
                        while ((pe = readdir(pd)) != NULL && nc->pid < 0) {
                            if (!isdigit(*pe->d_name)) continue;
                            char fd_dir[64];
                            snprintf(fd_dir, sizeof(fd_dir), "/proc/%s/fd", pe->d_name);
                            DIR *fdd = opendir(fd_dir);
                            if (!fdd) continue;
                            struct dirent *fde;
                            while ((fde = readdir(fdd)) != NULL) {
                                char fd_path[128], link_target[128] = {0};
                                snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd/%s",
                                         pe->d_name, fde->d_name);
                                if (readlink(fd_path, link_target, sizeof(link_target)-1) > 0) {
                                    if (strcmp(link_target, inode_str) == 0) {
                                        nc->pid = atoi(pe->d_name);
                                        break;
                                    }
                                }
                            }
                            closedir(fdd);
                        }
                        closedir(pd);
                    }
                }
                current_net_count++;
            }
            fclose(f);
        }

        /* Yeni bağlantıları tespit et ve gönder */
        if (initialized) {
            for (int i = 0; i < current_net_count; i++) {
                int is_new = 1;
                for (int j = 0; j < previous_net_count; j++) {
                    if (previous_nets[j].local_port  == current_nets[i].local_port  &&
                        previous_nets[j].remote_port == current_nets[i].remote_port &&
                        strcmp(previous_nets[j].remote_ip, current_nets[i].remote_ip) == 0) {
                        is_new = 0; break;
                    }
                }
                if (!is_new) continue;

                long long ts = get_ts();
                char msg[512];
                snprintf(msg, sizeof(msg),
                    "{\"agent_id\":\"%s\",\"os\":\"linux\",\"type\":\"network_new\","
                    "\"ts\":%lld,\"proto\":\"TCP\",\"pid\":%d,"
                    "\"local_ip\":\"%s\",\"local_port\":%d,"
                    "\"remote_ip\":\"%s\",\"remote_port\":%d}",
                    global_agent_id, ts, current_nets[i].pid,
                    current_nets[i].local_ip,  current_nets[i].local_port,
                    current_nets[i].remote_ip, current_nets[i].remote_port);
                safe_encrypt_send(soc, msg);
            }
        }

        memcpy(previous_nets, current_nets, sizeof(NetConn) * current_net_count);
        previous_net_count = current_net_count;
        initialized = 1;
        sleep(3);
    }
    return NULL;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);  /* journald icin unbuffered */
    init_tls_ctx();  /* Phase 5: TLS context yukle (mTLS) */
    GetAgentID();
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    while (1) {
        current_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(current_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) >= 0) {
            /* Phase 5: TLS mTLS handshake */
            if (tls_connect_wrap(current_sock) == 0) {
                pthread_t t1, t2, t3, t4;
                pthread_create(&t1, NULL, ShellThread,   &current_sock);
                pthread_create(&t2, NULL, MetricsThread, &current_sock);
                pthread_create(&t3, NULL, ProcessThread, &current_sock);
                pthread_create(&t4, NULL, NetworkThread, &current_sock);

                pthread_join(t1, NULL); /* Shell thread kopana kadar bekle */

                pthread_cancel(t2);
                pthread_cancel(t3);
                pthread_cancel(t4);
            } else {
                fprintf(stderr, "[!] TLS baglantisi kurulamadi, yeniden deneniyor...\n");
            }
        }
        close(current_sock);
        sleep(5);
    }
    return 0;
}