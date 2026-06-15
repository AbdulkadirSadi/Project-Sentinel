/*
 * sentinel_ebpf.c — Sentinel XDR Kernel-Level Process Monitor (Phase 6)
 *
 * Linux Kernel Connector (CN_PROC) kullanarak kernel'den gercek zamanli
 * process olaylarini alir. Bu Ring-0 kaynaklı kernel eventleri:
 *   - PROC_EVENT_EXEC : yeni process baslangici (execve syscall sonrasi)
 *   - PROC_EVENT_FORK : fork/clone
 *   - PROC_EVENT_EXIT : process sonlandi
 *
 * Mimari:
 *   Kernel --> [Netlink Connector] --> sentinel_ebpf --> Go C2 (HTTP POST)
 *
 * Derleme:
 *   gcc -o sentinel_ebpf sentinel_ebpf.c -lpthread
 *
 * Kullanim (root gerektirir):
 *   sudo ./sentinel_ebpf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <fcntl.h>

/* Networking */
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* Linux Kernel Connector */
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <linux/netlink.h>

/* ── Konfigürasyon ────────────────────────────────────────────────────────── */
#define C2_HOST     "127.0.0.1"
#define C2_PORT     8081
#define AGENT_ID_FILE "/proc/self/cgroup"   /* agent_id üretmek için */
#define MAX_JSON    2048

/* ── Global ajan kimliği ──────────────────────────────────────────────────── */
static char g_agent_id[64] = "ebpf-monitor";
static volatile int g_running = 1;

/* ── Yardımcı: /proc/<pid>/comm oku ─────────────────────────────────────── */
static void read_comm(pid_t pid, char *out, size_t sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) { strncpy(out, "?", sz); return; }
    if (!fgets(out, (int)sz, f)) strncpy(out, "?", sz);
    fclose(f);
    /* newline temizle */
    size_t l = strlen(out);
    if (l > 0 && out[l-1] == '\n') out[l-1] = '\0';
}

/* ── Yardımcı: /proc/<pid>/exe readlink ─────────────────────────────────── */
static void read_exe(pid_t pid, char *out, size_t sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t n = readlink(path, out, sz - 1);
    if (n < 0) strncpy(out, "?", sz);
    else out[n] = '\0';
}

/* ── Yardımcı: /proc/<pid>/cmdline ──────────────────────────────────────── */
static void read_cmdline(pid_t pid, char *out, size_t sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *f = fopen(path, "r");
    if (!f) { strncpy(out, "?", sz); return; }
    size_t n = fread(out, 1, sz - 1, f);
    fclose(f);
    out[n] = '\0';
    /* cmdline NUL-separated → space */
    for (size_t i = 0; i < n; i++)
        if (out[i] == '\0') out[i] = ' ';
    /* JSON güvenli: çift tırnakları kaldır */
    for (size_t i = 0; i < n; i++)
        if (out[i] == '"' || out[i] == '\\') out[i] = '\'';
}

/* ── HTTP POST to Go C2 ──────────────────────────────────────────────────── */
static void post_event(const char *json_body) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct timeval tv = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(C2_PORT);
    inet_pton(AF_INET, C2_HOST, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock); return;
    }

    size_t body_len = strlen(json_body);
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "POST /api/ebpf-event HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "X-Internal-Secret: sentinel-internal-ai-secret-2024\r\n"
        "Connection: close\r\n\r\n",
        C2_HOST, C2_PORT, body_len);

    send(sock, header, hlen, 0);
    send(sock, json_body, body_len, 0);

    /* Yanıtı oku (discard) */
    char resp[256];
    recv(sock, resp, sizeof(resp)-1, 0);
    close(sock);
}

/* ── Kernel Netlink Connector'ı etkinleştir ──────────────────────────────── */
static int set_proc_events_listen(int sock, int enable) {
    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__((__packed__)) {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } nlcn_msg;

    memset(&nlcn_msg, 0, sizeof(nlcn_msg));
    nlcn_msg.nl_hdr.nlmsg_len  = sizeof(nlcn_msg);
    nlcn_msg.nl_hdr.nlmsg_pid  = getpid();
    nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;
    nlcn_msg.cn_msg.id.idx     = CN_IDX_PROC;
    nlcn_msg.cn_msg.id.val     = CN_VAL_PROC;
    nlcn_msg.cn_msg.len        = sizeof(enum proc_cn_mcast_op);
    nlcn_msg.cn_mcast          = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

    if (send(sock, &nlcn_msg, sizeof(nlcn_msg), 0) == -1) {
        perror("[eBPF] set_proc_events_listen");
        return -1;
    }
    return 0;
}

/* ── Ana olay döngüsü ────────────────────────────────────────────────────── */
static void handle_proc_events(int sock) {
    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__((__packed__)) {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
        };
    } nlcn_msg;

    while (g_running) {
        ssize_t rc = recv(sock, &nlcn_msg, sizeof(nlcn_msg), 0);
        if (rc == 0) break;
        if (rc == -1) {
            if (errno == EINTR) continue;
            perror("[eBPF] recv");
            break;
        }

        struct proc_event *ev = &nlcn_msg.proc_ev;
        long long ts = (long long)time(NULL);
        char json[MAX_JSON];
        char comm[128] = {0};
        char exe[512]  = {0};
        char cmd[512]  = {0};

        switch (ev->what) {

        case PROC_EVENT_EXEC: {
            pid_t pid = ev->event_data.exec.process_pid;
            read_comm(pid, comm, sizeof(comm));
            read_exe(pid, exe, sizeof(exe));
            read_cmdline(pid, cmd, sizeof(cmd));

            snprintf(json, sizeof(json),
                "{\"agent_id\":\"%s\",\"type\":\"ebpf_exec\","
                "\"ts\":%lld,\"pid\":%d,\"pname\":\"%s\","
                "\"exe_path\":\"%s\",\"cmdline\":\"%s\","
                "\"source\":\"kernel_connector\"}",
                g_agent_id, ts, pid, comm, exe, cmd);

            printf("[KERNEL] EXEC  pid=%-6d comm=%-20s exe=%s\n", pid, comm, exe);
            post_event(json);
            break;
        }

        case PROC_EVENT_FORK: {
            pid_t child_pid = ev->event_data.fork.child_pid;
            pid_t parent_pid = ev->event_data.fork.parent_pid;
            read_comm(child_pid, comm, sizeof(comm));

            snprintf(json, sizeof(json),
                "{\"agent_id\":\"%s\",\"type\":\"ebpf_fork\","
                "\"ts\":%lld,\"pid\":%d,\"ppid\":%d,\"pname\":\"%s\","
                "\"source\":\"kernel_connector\"}",
                g_agent_id, ts, child_pid, parent_pid, comm);

            printf("[KERNEL] FORK  child=%-6d parent=%-6d comm=%s\n",
                   child_pid, parent_pid, comm);
            post_event(json);
            break;
        }

        case PROC_EVENT_EXIT: {
            pid_t pid = ev->event_data.exit.process_pid;
            int   ec  = (int)ev->event_data.exit.exit_code;

            snprintf(json, sizeof(json),
                "{\"agent_id\":\"%s\",\"type\":\"ebpf_exit\","
                "\"ts\":%lld,\"pid\":%d,\"exit_code\":%d,"
                "\"source\":\"kernel_connector\"}",
                g_agent_id, ts, pid, ec);

            printf("[KERNEL] EXIT  pid=%-6d code=%d\n", pid, ec);
            post_event(json);
            break;
        }

        case PROC_EVENT_UID: {
            /* UID değişimi — privilege escalation göstergesi */
            pid_t pid   = ev->event_data.id.process_pid;
            uid_t old_u = ev->event_data.id.r.ruid;
            uid_t new_u = ev->event_data.id.e.euid;
            read_comm(pid, comm, sizeof(comm));

            snprintf(json, sizeof(json),
                "{\"agent_id\":\"%s\",\"type\":\"ebpf_uid_change\","
                "\"ts\":%lld,\"pid\":%d,\"pname\":\"%s\","
                "\"old_uid\":%u,\"new_uid\":%u,"
                "\"source\":\"kernel_connector\"}",
                g_agent_id, ts, pid, comm, old_u, new_u);

            if (new_u == 0 && old_u != 0) {
                printf("[KERNEL] !!! UID->ROOT pid=%-6d comm=%s (old_uid=%u)\n",
                       pid, comm, old_u);
            }
            post_event(json);
            break;
        }

        default:
            break;
        }
    }
}

/* ── Sinyal işleyici ─────────────────────────────────────────────────────── */
static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* ── main ────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* Agent ID: hostname kullan */
    gethostname(g_agent_id, sizeof(g_agent_id));

    printf("[Sentinel eBPF] Kernel Process Monitor baslatildi\n");
    printf("[Sentinel eBPF] C2: http://%s:%d\n", C2_HOST, C2_PORT);
    printf("[Sentinel eBPF] Kaynak: Linux Kernel Connector (CN_PROC)\n");
    printf("[Sentinel eBPF] Ring: 0 kaynaklı eventler (kernel connector)\n\n");

    int sock = -1;
    while (g_running) {
        /* Netlink socket aç */
        sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
        if (sock == -1) {
            fprintf(stderr, "[eBPF] socket() basarisiz (root gerektirir): %s\n",
                    strerror(errno));
            sleep(5);
            continue;
        }

        struct sockaddr_nl nl_addr;
        memset(&nl_addr, 0, sizeof(nl_addr));
        nl_addr.nl_family = AF_NETLINK;
        nl_addr.nl_groups = CN_IDX_PROC;
        nl_addr.nl_pid    = getpid();

        if (bind(sock, (struct sockaddr *)&nl_addr, sizeof(nl_addr)) == -1) {
            perror("[eBPF] bind");
            close(sock);
            sleep(5);
            continue;
        }

        if (set_proc_events_listen(sock, 1) == -1) {
            close(sock);
            sleep(5);
            continue;
        }

        printf("[eBPF] Kernel eventleri dinleniyor...\n");
        handle_proc_events(sock);

        set_proc_events_listen(sock, 0);
        close(sock);

        if (g_running) {
            printf("[eBPF] Baglanti koptu, 5s sonra yeniden deneniyor...\n");
            sleep(5);
        }
    }

    printf("[eBPF] Durduruldu.\n");
    return 0;
}
