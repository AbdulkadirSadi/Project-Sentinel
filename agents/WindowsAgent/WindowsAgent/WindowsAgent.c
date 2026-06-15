#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup") // Hayalet Modu
#undef UNICODE
#undef _UNICODE
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable: 4996)

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <TlHelp32.h>
#include <stdbool.h>
/* Phase 5: Schannel TLS */
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <sspi.h>
/* Phase 7: ETW kernel telemetry */
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "tdh.lib")

#define DEFAULT_PORT "8080"
#define DEFAULT_IP "192.168.146.1"
#define SECRET_KEY "EDR_SUPER_SECRET_KEY"
#define MAX_PROCESS_HISTORY 2048
#define MAX_NETWORK_HISTORY 2048
#define API_PORT            8081
#define MAX_FILE_SCAN       (10 * 1024 * 1024)
/* Sertifika Subject - mTLS icin agent kimlik dogrulamasi */
#define TLS_CERT_SUBJECT    L"sentinel-agent"
#define ETW_SESSION_NAME    L"SentinelXDRKernel"

CRITICAL_SECTION send_cs;
char global_agent_id[128] = { 0 };

/* Debug log uretim modunda devre disi — SUBSYSTEM:windows aktif */
#define dbg(msg)      ((void)0)
#define dbgf(fmt,...) ((void)0)

/* ── Forward declarations (MSVC icin) ───────────────────────────────────── */
void safe_encrypt_send(SOCKET soc, const char* message);

/* ── Schannel TLS globals (Phase 5) ─────────────────────────────────────── */
static CredHandle  g_hCred;
static CtxtHandle  g_hCtxt;
static BOOL        g_tls_ok  = FALSE;
static SecPkgContext_StreamSizes g_StreamSizes;

/* Handle gecerlilik takibi */
static BOOL g_cred_valid = FALSE;
static BOOL g_ctx_valid  = FALSE;

/* Schannel: onceki oturumu temizle */
static void tls_cleanup(void) {
    if (g_ctx_valid)  { DeleteSecurityContext(&g_hCtxt);  g_ctx_valid  = FALSE; }
    if (g_cred_valid) { FreeCredentialsHandle(&g_hCred);  g_cred_valid = FALSE; }
    SecInvalidateHandle(&g_hCtxt);
    SecInvalidateHandle(&g_hCred);
    g_tls_ok = FALSE;
}

/* Schannel: kimlik bilgisi al */
static BOOL tls_acquire_cred(void) {
    /* Onceki gecersiz handle'i temizle */
    if (g_cred_valid) { FreeCredentialsHandle(&g_hCred); g_cred_valid = FALSE; }
    SecInvalidateHandle(&g_hCred);

    SCHANNEL_CRED sc = { 0 };
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    /*
     * SCH_CRED_MANUAL_CRED_VALIDATION      : self-signed sertifika icin el dogrulamasi
     * SCH_CRED_NO_SERVERNAME_CHECK          : CN/SAN uyumsuzlugunu yoksay
     * SCH_CRED_IGNORE_NO_REVOCATION_CHECK   : CRL bulunamazsa hata verme
     * SCH_CRED_IGNORE_REVOCATION_OFFLINE    : CRL cevrimdisi ise hata verme
     */
    sc.dwFlags = SCH_CRED_NO_DEFAULT_CREDS
               | SCH_CRED_MANUAL_CRED_VALIDATION
               | SCH_CRED_NO_SERVERNAME_CHECK
               | SCH_CRED_IGNORE_NO_REVOCATION_CHECK
               | SCH_CRED_IGNORE_REVOCATION_OFFLINE;
    /* grbitEnabledProtocols=0: OS'un destekledigi en iyi versiyonu otomatik sec */
    sc.grbitEnabledProtocols = 0;

    TimeStamp ts;
    SECURITY_STATUS ss = AcquireCredentialsHandleA(
        NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
        NULL, &sc, NULL, NULL, &g_hCred, &ts);
    dbgf("  AcquireCredentialsHandle: 0x%08X (%s)", (unsigned)ss,
         ss == SEC_E_OK ? "OK" : "HATA");
    if (ss == SEC_E_OK) g_cred_valid = TRUE;
    return ss == SEC_E_OK;
}

/* Schannel: TLS el sikisma — tam yeniden yazilmis */
static BOOL tls_connect_schannel(SOCKET sock) {
    /* Her denemeden once onceki durumu temizle */
    tls_cleanup();

    dbg("  [TLS] tls_acquire_cred cagiriliyor...");
    if (!tls_acquire_cred()) {
        dbg("  [TLS] tls_acquire_cred BASARISIZ - erken cikis");
        return FALSE;
    }
    dbg("  [TLS] Credential OK, ISC baslatiliyor...");

    /* ISC_REQ_ALLOCATE_MEMORY: Schannel cikis tamponlari kendisi ayirtsin.
     * Bu flag OLMADAN NULL tampon gecilince 0x80090300 SEC_E_INSUFFICIENT_MEMORY
     * hatasi olusur. Bu, sorunun kok nedeniydi. */
    DWORD dwFlags = ISC_REQ_SEQUENCE_DETECT  |
                    ISC_REQ_REPLAY_DETECT    |
                    ISC_REQ_CONFIDENTIALITY  |
                    ISC_REQ_STREAM           |
                    ISC_REQ_ALLOCATE_MEMORY;

    SecBuffer    outBufs[1] = {{ 0, SECBUFFER_TOKEN, NULL }};
    SecBufferDesc outDesc   = { SECBUFFER_VERSION, 1, outBufs };
    TimeStamp     ts;

    /* context handle'ini gecersiz olarak isaretle (ilk cagri) */
    SecInvalidateHandle(&g_hCtxt);

    SECURITY_STATUS ss = InitializeSecurityContextA(
        &g_hCred,
        NULL,          /* ilk cagri: mevcut context yok */
        DEFAULT_IP,    /* hedef sunucu adi (SNI) */
        dwFlags, 0,
        SECURITY_NATIVE_DREP,
        NULL, 0,       /* ilk cagri: giris tamponu yok */
        &g_hCtxt,      /* cikis: yeni context buraya yazilir */
        &outDesc,
        &dwFlags, &ts);

    dbgf("  [TLS] ISC ilk: 0x%08X (beklenen SEC_I_CONTINUE=0x%08X)",
         (unsigned)ss, (unsigned)SEC_I_CONTINUE_NEEDED);

    /* ISC_REQ_ALLOCATE_MEMORY ile Schannel bellek ayirtti, biz gonderip serbest birakiriz */
    if (outBufs[0].pvBuffer && outBufs[0].cbBuffer > 0) {
        int sent = send(sock, (char*)outBufs[0].pvBuffer, (int)outBufs[0].cbBuffer, 0);
        dbgf("  [TLS] ClientHello gonderildi: %d byte (tampon=%u)",
             sent, outBufs[0].cbBuffer);
        FreeContextBuffer(outBufs[0].pvBuffer);
        outBufs[0].pvBuffer = NULL;
    } else {
        dbgf("  [TLS] ClientHello tamponu bos! pvBuffer=%p cbBuffer=%u",
             outBufs[0].pvBuffer, outBufs[0].cbBuffer);
    }

    if (ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_INCOMPLETE_MESSAGE) {
        dbgf("  [TLS] ISC ilk adimda bitti: 0x%08X - cikiliyor", (unsigned)ss);
        return FALSE;
    }

    g_ctx_valid = TRUE; /* context artik gecerli */

    /* Handshake dongu */
    char ibuf[32768];
    int  ibuf_len  = 0;
    int  loop_iter = 0;

    while (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE) {
        loop_iter++;
        dbgf("  [TLS] Dongu #%d — sunucudan veri bekleniyor...", loop_iter);

        int n = recv(sock, ibuf + ibuf_len,
                     (int)(sizeof(ibuf) - ibuf_len), 0);
        dbgf("  [TLS] recv=%d WSAErr=%d", n, WSAGetLastError());

        if (n <= 0) {
            dbgf("  [TLS] Baglanti kapandi (n=%d)", n);
            return FALSE;
        }
        ibuf_len += n;

        SecBuffer inBufs[2] = {
            { (ULONG)ibuf_len, SECBUFFER_TOKEN, ibuf },
            { 0,               SECBUFFER_EMPTY, NULL  }
        };
        SecBuffer    outBuf2[1] = {{ 0, SECBUFFER_TOKEN, NULL }};
        SecBufferDesc inDesc    = { SECBUFFER_VERSION, 2, inBufs  };
        SecBufferDesc outDesc2  = { SECBUFFER_VERSION, 1, outBuf2 };

        ss = InitializeSecurityContextA(
            &g_hCred,
            &g_hCtxt,  /* mevcut context */
            NULL,      /* devam cagrilarinda hedef adi NULL */
            dwFlags, 0,
            SECURITY_NATIVE_DREP,
            &inDesc, 0,
            NULL,      /* devam cagrilarinda cikis context NULL */
            &outDesc2,
            &dwFlags, &ts);

        dbgf("  [TLS] ISC dongu #%d: 0x%08X", loop_iter, (unsigned)ss);

        if (outBuf2[0].pvBuffer && outBuf2[0].cbBuffer > 0) {
            send(sock, (char*)outBuf2[0].pvBuffer, (int)outBuf2[0].cbBuffer, 0);
            FreeContextBuffer(outBuf2[0].pvBuffer);
            outBuf2[0].pvBuffer = NULL;
        }

        /* Fazla tampon verisi varsa basa tasi */
        if (inBufs[1].BufferType == SECBUFFER_EXTRA && inBufs[1].cbBuffer > 0) {
            memmove(ibuf, ibuf + ibuf_len - inBufs[1].cbBuffer,
                    inBufs[1].cbBuffer);
            ibuf_len = (int)inBufs[1].cbBuffer;
        } else {
            ibuf_len = 0;
        }
    }

    dbgf("  [TLS] Dongu bitti: ss=0x%08X (%s)",
         (unsigned)ss, ss == SEC_E_OK ? "BASARILI" : "BASARISIZ");

    if (ss != SEC_E_OK) return FALSE;

    QueryContextAttributes(&g_hCtxt, SECPKG_ATTR_STREAM_SIZES, &g_StreamSizes);
    g_tls_ok = TRUE;
    return TRUE;
}

/* Schannel sifreleme ile send */
static int tls_send_sch(SOCKET sock, const char* data, int len) {
    if (!g_tls_ok) return send(sock, data, len, 0);
    DWORD hdr = g_StreamSizes.cbHeader;
    DWORD trl = g_StreamSizes.cbTrailer;
    DWORD msg = g_StreamSizes.cbMaximumMessage;
    if ((DWORD)len > msg) len = (int)msg;
    BYTE* buf = (BYTE*)malloc(hdr + len + trl);
    if (!buf) return -1;
    memcpy(buf + hdr, data, len);
    SecBuffer bufs[4];
    SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };
    bufs[0].pvBuffer = buf;        bufs[0].cbBuffer = hdr; bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
    bufs[1].pvBuffer = buf + hdr;  bufs[1].cbBuffer = len; bufs[1].BufferType = SECBUFFER_DATA;
    bufs[2].pvBuffer = buf + hdr + len; bufs[2].cbBuffer = trl; bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
    bufs[3].pvBuffer = NULL; bufs[3].cbBuffer = 0; bufs[3].BufferType = SECBUFFER_EMPTY;
    EncryptMessage(&g_hCtxt, 0, &desc, 0);
    int total = hdr + len + trl;
    send(sock, (char*)buf, total, 0);
    free(buf);
    return len;
}

/* Schannel sifre cozme ile recv */
static int tls_recv_sch(SOCKET sock, char* data, int maxlen) {
    if (!g_tls_ok) return recv(sock, data, maxlen, 0);
    char ibuf[20000]; int ilen = 0;
    while (1) {
        int n = recv(sock, ibuf + ilen, sizeof(ibuf) - ilen, 0);
        if (n <= 0) return n;
        ilen += n;
        SecBuffer bufs[4];
        SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };
        bufs[0].pvBuffer = ibuf; bufs[0].cbBuffer = ilen; bufs[0].BufferType = SECBUFFER_DATA;
        bufs[1].pvBuffer = NULL; bufs[1].cbBuffer = 0; bufs[1].BufferType = SECBUFFER_EMPTY;
        bufs[2].pvBuffer = NULL; bufs[2].cbBuffer = 0; bufs[2].BufferType = SECBUFFER_EMPTY;
        bufs[3].pvBuffer = NULL; bufs[3].cbBuffer = 0; bufs[3].BufferType = SECBUFFER_EMPTY;
        SECURITY_STATUS ss = DecryptMessage(&g_hCtxt, &desc, 0, NULL);
        if (ss == SEC_E_INCOMPLETE_MESSAGE) continue;
        if (ss != SEC_E_OK) return -1;
        for (int i = 1; i < 4; i++) {
            if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0) {
                int copy = min(bufs[i].cbBuffer, (DWORD)maxlen);
                memcpy(data, bufs[i].pvBuffer, copy);
                return copy;
            }
        }
        return 0;
    }
}

/* ── ETW Kernel Telemetry (Phase 7) ─────────────────────────────────────── */
/* Microsoft-Windows-Kernel-Process GUID */
static const GUID KernelProcessGuid =
    {0x22fb2cd6,0x0e7b,0x422b,{0xa0,0xc7,0x2f,0xad,0x1f,0xd0,0xe7,0x16}};

static SOCKET g_etw_sock = INVALID_SOCKET;  /* C2 soketini ETW callback'e ilet */

/* ETW event callback: kernel process/network eventlerini isle */
VOID WINAPI EtwEventCallback(PEVENT_RECORD pEvent) {
    if (!IsEqualGUID(&pEvent->EventHeader.ProviderId, &KernelProcessGuid)) return;
    if (g_etw_sock == INVALID_SOCKET) return;

    USHORT id   = pEvent->EventHeader.EventDescriptor.Id;
    DWORD  pid  = pEvent->EventHeader.ProcessId;
    LONGLONG ts = (LONGLONG)(pEvent->EventHeader.TimeStamp.QuadPart / 10000000LL);

    char msg[1024] = {0};
    char pname[256] = "?";

    /* ETW: Id=1 = ProcessStart, Id=2 = ProcessStop */
    if (id == 1) {
        /* ProcessStart: ImageName genellikle offset 0'da */
        if (pEvent->UserDataLength > 0) {
            /* Unicode string -> ASCII */
            WideCharToMultiByte(CP_ACP, 0,
                (LPCWSTR)pEvent->UserData, -1,
                pname, sizeof(pname) - 1, NULL, NULL);
        }
        snprintf(msg, sizeof(msg),
            "{\"agent_id\":\"%s\",\"type\":\"etw_process_start\","
            "\"ts\":%lld,\"pid\":%lu,\"pname\":\"%s\","
            "\"source\":\"etw_kernel\"}",
            global_agent_id, (long long)ts, pid, pname);
        safe_encrypt_send(g_etw_sock, msg);
    } else if (id == 2) {
        snprintf(msg, sizeof(msg),
            "{\"agent_id\":\"%s\",\"type\":\"etw_process_stop\","
            "\"ts\":%lld,\"pid\":%lu,\"source\":\"etw_kernel\"}",
            global_agent_id, (long long)ts, pid);
        safe_encrypt_send(g_etw_sock, msg);
    }
}

DWORD WINAPI ETWThread(LPVOID lpParam) {
    g_etw_sock = *(SOCKET*)lpParam;

    /* EVENT_TRACE_PROPERTIES yapisi + isim alani */
    ULONG bufSz = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(ETW_SESSION_NAME) + 256;
    EVENT_TRACE_PROPERTIES* pProps = (EVENT_TRACE_PROPERTIES*)calloc(1, bufSz);
    if (!pProps) return 1;
    pProps->Wnode.BufferSize    = bufSz;
    pProps->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    pProps->Wnode.ClientContext  = 1;  /* QPC */
    pProps->LogFileMode          = EVENT_TRACE_REAL_TIME_MODE;
    pProps->LoggerNameOffset     = sizeof(EVENT_TRACE_PROPERTIES);

    TRACEHANDLE hSession = 0;
    /* Onceki kalan oturumu temizle */
    ControlTraceW(0, ETW_SESSION_NAME, pProps, EVENT_TRACE_CONTROL_STOP);
    memset(((BYTE*)pProps) + sizeof(EVENT_TRACE_PROPERTIES), 0, bufSz - sizeof(EVENT_TRACE_PROPERTIES));

    ULONG rc = StartTraceW(&hSession, ETW_SESSION_NAME, pProps);
    if (rc != ERROR_SUCCESS && rc != ERROR_ALREADY_EXISTS) {
        free(pProps); return 1;
    }

    /* Kernel-Process provider'i etkinlestir */
    EnableTraceEx2(hSession, &KernelProcessGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION, 0x10, 0, 0, NULL);

    /* Consumer ayarla */
    EVENT_TRACE_LOGFILEA logFile = {0};
    logFile.LoggerName          = "SentinelXDRKernel";
    logFile.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EtwEventCallback;

    TRACEHANDLE hConsumer = OpenTraceA(&logFile);
    if (hConsumer != INVALID_PROCESSTRACE_HANDLE) {
        ProcessTrace(&hConsumer, 1, NULL, NULL);  /* Bloke eder */
        CloseTrace(hConsumer);
    }

    ControlTraceW(hSession, ETW_SESSION_NAME, pProps, EVENT_TRACE_CONTROL_STOP);
    free(pProps);
    return 0;
}


DWORD previous_pids[MAX_PROCESS_HISTORY];
int previous_pid_count = 0;

typedef struct { DWORD localAddr, localPort, remoteAddr, remotePort, owningPid; int protocol; } NetConnection;
NetConnection previous_nets[MAX_NETWORK_HISTORY];
int previous_net_count = 0;

ULARGE_INTEGER lastCPU, lastSysCPU, lastUserCPU, lastIdleCPU;
int numProcessors;
SOCKET current_sock = INVALID_SOCKET;

// UUID Alıcı
void GetAgentID() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        DWORD size = sizeof(global_agent_id);
        RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, (LPBYTE)global_agent_id, &size);
        RegCloseKey(hKey);
    }
    else {
        strcpy_s(global_agent_id, sizeof(global_agent_id), "UNKNOWN-WINDOWS-UUID");
    }
}

// Unix timestamp (saniye)
static long long GetTimestampUnix() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    // Windows epoch (1601) -> Unix epoch (1970) farkı: 116444736000000000 * 100ns
    return (long long)((uli.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

// Process exe yolu, cmdline ve kullanıcı adını doldurur
static void GetProcessDetails(DWORD pid, char* exe_path, int exe_size, char* username, int user_size) {
    exe_path[0] = '\0'; username[0] = '\0';
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return;

    // Exe tam yolu
    DWORD pathLen = (DWORD)exe_size;
    QueryFullProcessImageNameA(hProc, 0, exe_path, &pathLen);

    // Kullanıcı adı (process token üzerinden)
    HANDLE hToken = NULL;
    if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        char info_buf[512] = { 0 };
        DWORD info_len = sizeof(info_buf);
        if (GetTokenInformation(hToken, TokenUser, info_buf, info_len, &info_len)) {
            TOKEN_USER* tu = (TOKEN_USER*)info_buf;
            char name[128] = { 0 }, domain[128] = { 0 };
            DWORD nlen = sizeof(name), dlen = sizeof(domain);
            SID_NAME_USE snu;
            if (LookupAccountSidA(NULL, tu->User.Sid, name, &nlen, domain, &dlen, &snu))
                snprintf(username, user_size, "%s\\%s", domain, name);
        }
        CloseHandle(hToken);
    }
    CloseHandle(hProc);
}

void safe_encrypt_send(SOCKET soc, const char* message) {
    EnterCriticalSection(&send_cs);
    int len = (int)strlen(message);
    char* enc = (char*)malloc(len + 1);
    strcpy_s(enc, len + 1, message);
    int key_len = (int)strlen(SECRET_KEY);
    for (int i = 0; i < len; i++) enc[i] ^= SECRET_KEY[i % key_len];

    char* hex = (char*)malloc(len * 2 + 2);
    for (int i = 0; i < len; i++) snprintf(hex + (i * 2), 3, "%02X", (unsigned char)enc[i]);
    hex[len * 2] = '\n';
    hex[len * 2 + 1] = '\0';

    /* Phase 5: Schannel TLS veya plain send */
    tls_send_sch(soc, hex, (int)strlen(hex));
    free(enc); free(hex);
    LeaveCriticalSection(&send_cs);
}

void decrypt_command(char* hex_str, char* out_plain) {
    int len = (int)strlen(hex_str);
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

void escape_json_string(const char* input, char* output) {
    int j = 0;
    for (int i = 0; input[i]; i++) {
        if (input[i] == '"' || input[i] == '\\') {
            output[j++] = '\\';
            output[j++] = input[i];
        }
        else if (input[i] == '\n') {
            output[j++] = '\\';
            output[j++] = 'n';
        }
        else if (input[i] == '\r') {
            // \r karakterini yoksayıyoruz
        }
        else {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

// ── FileWatcher ──────────────────────────────────────────────────────────────

static const char B64W[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char* fw_base64w(const unsigned char* data, size_t len, size_t* out_len) {
    size_t enc = 4 * ((len + 2) / 3);
    char* out = (char*)malloc(enc + 1);
    if (!out) return NULL;
    size_t i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        out[j++] = B64W[(data[i]   >> 2) & 0x3F];
        out[j++] = B64W[((data[i] & 3) << 4) | (data[i+1] >> 4)];
        out[j++] = B64W[((data[i+1] & 0xF) << 2) | (data[i+2] >> 6)];
        out[j++] = B64W[data[i+2] & 0x3F];
    }
    if (i < len) {
        out[j++] = B64W[(data[i] >> 2) & 0x3F];
        if (i + 1 < len) {
            out[j++] = B64W[((data[i] & 3) << 4) | (data[i+1] >> 4)];
            out[j++] = B64W[(data[i+1] & 0xF) << 2];
        } else {
            out[j++] = B64W[(data[i] & 3) << 4];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    out[j] = '\0';
    if (out_len) *out_len = j;
    return out;
}

static int fw_is_exec_w(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    unsigned char mg[4] = {0};
    int n = (int)fread(mg, 1, 4, f);
    fclose(f);
    if (n < 2) return 0;
    if (mg[0] == 0x7F && mg[1] == 'E' && mg[2] == 'L' && mg[3] == 'F') return 1;
    if (mg[0] == 'M' && mg[1] == 'Z') return 1;
    return 0;
}

static void fw_send_scan_w(const char* fpath) {
    if (!fw_is_exec_w(fpath)) return;

    HANDLE hf = CreateFileA(fpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER fsz; fsz.QuadPart = 0;
    GetFileSizeEx(hf, &fsz);
    if (fsz.QuadPart > MAX_FILE_SCAN || fsz.QuadPart < 64) { CloseHandle(hf); return; }

    size_t fsize = (size_t)fsz.QuadPart;
    unsigned char* buf = (unsigned char*)malloc(fsize);
    if (!buf) { CloseHandle(hf); return; }
    DWORD nread = 0;
    ReadFile(hf, buf, (DWORD)fsize, &nread, NULL);
    CloseHandle(hf);
    if (nread < 64) { free(buf); return; }

    size_t b64len;
    char* b64 = fw_base64w(buf, nread, &b64len);
    free(buf);
    if (!b64) return;

    const char* fname = strrchr(fpath, '\\');
    if (!fname) fname = strrchr(fpath, '/');
    fname = fname ? fname + 1 : fpath;

    char esc_path[2048] = {0};
    char esc_name[512]  = {0};
    escape_json_string(fpath, esc_path);
    escape_json_string(fname, esc_name);

    size_t bsz  = b64len + 2048;
    char*  body = (char*)malloc(bsz);
    if (!body) { free(b64); return; }
    snprintf(body, bsz,
        "{\"agent_id\":\"%s\",\"file_name\":\"%s\","
        "\"file_path\":\"%s\",\"exe_b64\":\"%s\","
        "\"source\":\"auto_scan\",\"categorize\":false}",
        global_agent_id, esc_name, esc_path, b64);
    free(b64);
    size_t body_len = strlen(body);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { free(body); return; }
    DWORD tv = 10000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(API_PORT);
    inet_pton(AF_INET, DEFAULT_IP, &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock); free(body); return;
    }

    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "POST /api/file-scan HTTP/1.0\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "\r\n",
        DEFAULT_IP, API_PORT, body_len);
    send(sock, header, hlen, 0);

    size_t sent = 0;
    while (sent < body_len) {
        int s = send(sock, body + sent, (int)(body_len - sent), 0);
        if (s <= 0) break;
        sent += (size_t)s;
    }
    char resp[128] = {0};
    recv(sock, resp, sizeof(resp) - 1, 0);
    closesocket(sock);
    free(body);
}

typedef struct {
    char   path[MAX_PATH];
    HANDLE hDir;
    OVERLAPPED ov;
    BYTE   buf[8192];
} WinWatch;

DWORD WINAPI FileWatchThread(LPVOID lpParam) {
    (void)lpParam;
    char ud[MAX_PATH]={0}, dd[MAX_PATH]={0}, hd[MAX_PATH]={0};
    char* up = getenv("USERPROFILE");
    if (up) {
        snprintf(ud, MAX_PATH, "%s\\Downloads", up);
        snprintf(dd, MAX_PATH, "%s\\Desktop",   up);
        snprintf(hd, MAX_PATH, "%s",             up);
    }
    const char* dirs[] = {
        "C:\\Windows\\Temp", "C:\\Temp", "C:\\Users\\Public\\Downloads",
        ud[0]?ud:NULL, dd[0]?dd:NULL, hd[0]?hd:NULL, NULL
    };
    int ndir = 0;
    for (int i = 0; dirs[i] && ndir < 8; i++) if (dirs[i][0]) ndir++;

    WinWatch* W = (WinWatch*)calloc(ndir, sizeof(WinWatch));
    if (!W) return 0;
    HANDLE evs[8]; int valid = 0;
    for (int i = 0, vi = 0; dirs[i] && vi < ndir; i++) {
        if (!dirs[i] || !dirs[i][0]) continue;
        strncpy_s(W[valid].path, MAX_PATH, dirs[i], _TRUNCATE);
        W[valid].hDir = CreateFileA(dirs[i], FILE_LIST_DIRECTORY,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OVERLAPPED, NULL);
        if (W[valid].hDir == INVALID_HANDLE_VALUE) continue;
        W[valid].ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        ReadDirectoryChangesW(W[valid].hDir, W[valid].buf, sizeof(W[valid].buf),
            FALSE, FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_SIZE,
            NULL, &W[valid].ov, NULL);
        evs[valid] = W[valid].ov.hEvent;
        valid++;
    }
    if (valid == 0) { free(W); return 0; }

    while (1) {
        DWORD idx = WaitForMultipleObjectsEx(valid, evs, FALSE, INFINITE, FALSE);
        if (idx >= (DWORD)valid) { Sleep(100); continue; }
        DWORD bytes = 0;
        GetOverlappedResult(W[idx].hDir, &W[idx].ov, &bytes, FALSE);
        if (bytes > 0) {
            FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)W[idx].buf;
            do {
                if (fni->Action == FILE_ACTION_ADDED ||
                    fni->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                    char fn[MAX_PATH] = {0};
                    WideCharToMultiByte(CP_ACP, 0, fni->FileName,
                        fni->FileNameLength/sizeof(WCHAR), fn, MAX_PATH-1, NULL, NULL);
                    char full[MAX_PATH];
                    snprintf(full, MAX_PATH, "%s\\%s", W[idx].path, fn);
                    Sleep(1000);
                    fw_send_scan_w(full);
                }
                if (!fni->NextEntryOffset) break;
                fni = (FILE_NOTIFY_INFORMATION*)((BYTE*)fni + fni->NextEntryOffset);
            } while (1);
        }
        ResetEvent(W[idx].ov.hEvent);
        ReadDirectoryChangesW(W[idx].hDir, W[idx].buf, sizeof(W[idx].buf),
            FALSE, FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_SIZE,
            NULL, &W[idx].ov, NULL);
    }
    free(W);
    return 0;
}

// ── Güvenli Yardımcı Fonksiyonlar ────────────────────────────────────────────

/* IP adresini doğrula: sadece a.b.c.d formatını (ve CIDR /xx ekini) kabul et */
static int is_safe_ip(const char* ip) {
    if (!ip || strlen(ip) == 0 || strlen(ip) > 43) return 0;
    const char* p = ip;
    int dots = 0, digits = 0;
    /* Sadece rakam, nokta ve / kabul et */
    while (*p) {
        if (*p >= '0' && *p <= '9') { digits++; }
        else if (*p == '.') { dots++; if (digits == 0 || digits > 3) return 0; digits = 0; }
        else if (*p == '/' && dots == 3) { p++; break; } /* CIDR prefix */
        else return 0;
        p++;
    }
    /* CIDR kontrolü */
    while (*p) { if (*p < '0' || *p > '9') return 0; p++; }
    return (dots == 3 && digits > 0 && digits <= 3);
}

/* Dosya yolunda path traversal (..) var mı kontrol et */
static int has_path_traversal(const char* path) {
    if (strstr(path, "..") != NULL) return 1;
    return 0;
}

/* system() yerine CreateProcessA — parametre enjeksiyonu engellenir */
static void run_netsh(const char* arg1, const char* arg2, const char* arg3, const char* arg4, const char* arg5) {
    char cmdline[1024];
    /* Argümanları doğrudan birleştiriyoruz — IP zaten doğrulanmış */
    snprintf(cmdline, sizeof(cmdline),
        "netsh advfirewall firewall %s %s %s %s %s",
        arg1 ? arg1 : "", arg2 ? arg2 : "",
        arg3 ? arg3 : "", arg4 ? arg4 : "",
        arg5 ? arg5 : "");

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

// ── ACTION:: Komut İşleyici ───────────────────────────────────────────────────
void handle_action(SOCKET soc, const char* action_str) {
    char action[64] = {0};
    char result_msg[512] = {0};
    long long ts = GetTimestampUnix();

    // "kill_process pid=1234" gibi parse et
    sscanf(action_str, "%63s", action);

    if (strncmp(action, "kill_process", 12) == 0) {
        DWORD pid = 0;
        sscanf(action_str + 12, " pid=%lu", &pid);
        if (pid > 0) {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (h && TerminateProcess(h, 1)) {
                CloseHandle(h);
                snprintf(result_msg, sizeof(result_msg),
                    "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                    "\"ts\":%lld,\"output\":\"[ACTION] kill_process: PID %lu sonlandirild\"}",
                    global_agent_id, ts, pid);
            } else {
                snprintf(result_msg, sizeof(result_msg),
                    "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                    "\"ts\":%lld,\"output\":\"[ACTION] kill_process HATA: PID %lu\"}",
                    global_agent_id, ts, pid);
            }
        }

    } else if (strncmp(action, "block_ip", 8) == 0 ||
               strncmp(action, "isolate_network", 15) == 0) {
        char ip[64] = {0};
        char* eq = strchr(action_str, '=');
        if (eq) strncpy_s(ip, sizeof(ip), eq + 1, _TRUNCATE);

        /* ── GÜVENLİK: IP doğrulama ── */
        if (!is_safe_ip(ip)) {
            snprintf(result_msg, sizeof(result_msg),
                "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                "\"ts\":%lld,\"output\":\"[ACTION] block_ip HATA: Geçersiz IP formatı reddedildi.\"}",
                global_agent_id, ts);
        } else {
            /* system() yerine CreateProcessA — injection güvenli */
            char rule_out[128], rule_in[128];
            snprintf(rule_out, sizeof(rule_out), "name=\"SENTINEL-BLOCK-OUT-%s\"", ip);
            snprintf(rule_in,  sizeof(rule_in),  "name=\"SENTINEL-BLOCK-IN-%s\"",  ip);
            /* Giden trafik: netsh advfirewall firewall add rule name=... dir=out action=block remoteip=IP */
            run_netsh("add", "rule", rule_out, "dir=out action=block", ip);
            run_netsh("add", "rule", rule_in,  "dir=in  action=block", ip);
            snprintf(result_msg, sizeof(result_msg),
                "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                "\"ts\":%lld,\"output\":\"[ACTION] IP engellendi: %s\"}",
                global_agent_id, ts, ip);
        }

    } else if (strncmp(action, "unblock_ip", 10) == 0) {
        char ip[64] = {0};
        char* eq = strchr(action_str, '=');
        if (eq) strncpy_s(ip, sizeof(ip), eq + 1, _TRUNCATE);

        /* ── GÜVENLİK: IP doğrulama ── */
        if (!is_safe_ip(ip)) {
            snprintf(result_msg, sizeof(result_msg),
                "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                "\"ts\":%lld,\"output\":\"[ACTION] unblock_ip HATA: Geçersiz IP formatı.\"}",
                global_agent_id, ts);
        } else {
            char rule_out[128], rule_in[128];
            snprintf(rule_out, sizeof(rule_out), "name=\"SENTINEL-BLOCK-OUT-%s\"", ip);
            snprintf(rule_in,  sizeof(rule_in),  "name=\"SENTINEL-BLOCK-IN-%s\"",  ip);
            run_netsh("delete", "rule", rule_out, "", "");
            run_netsh("delete", "rule", rule_in,  "", "");
            snprintf(result_msg, sizeof(result_msg),
                "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                "\"ts\":%lld,\"output\":\"[ACTION] IP engeli kaldirildi: %s\"}",
                global_agent_id, ts, ip);
        }

    } else if (strncmp(action, "quarantine_file", 15) == 0) {
        char path[MAX_PATH] = {0};
        char* eq = strchr(action_str, '=');
        if (eq) strncpy_s(path, sizeof(path), eq + 1, _TRUNCATE);

        /* ── GÜVENLİK: Path traversal koruması ── */
        if (has_path_traversal(path)) {
            snprintf(result_msg, sizeof(result_msg),
                "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                "\"ts\":%lld,\"output\":\"[ACTION] quarantine_file HATA: Geçersiz dosya yolu.\"}",
                global_agent_id, ts);
        } else if (strlen(path) > 0) {
            /* Önce C:\Sentinel\Quarantine'i dene, başarısız olursa %LOCALAPPDATA%\Sentinel\Quarantine */
            char qdir[MAX_PATH] = "C:\\Sentinel\\Quarantine";
            if (!CreateDirectoryA("C:\\Sentinel", NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                /* C:\ yazma izni yok — kullanıcı klasörüne geç */
                char* appdata = NULL;
                size_t appdata_len = 0;
                if (_dupenv_s(&appdata, &appdata_len, "LOCALAPPDATA") == 0 && appdata) {
                    snprintf(qdir, sizeof(qdir), "%s\\Sentinel\\Quarantine", appdata);
                    free(appdata);
                }
            }
            /* Hedef karantina klasörünü oluştur (zaten varsa hata vermez) */
            CreateDirectoryA(qdir, NULL);
            /* Alt klasörü de oluştur */
            {
                char parent[MAX_PATH];
                strncpy_s(parent, sizeof(parent), qdir, _TRUNCATE);
                char* sep = strrchr(parent, '\\');
                if (sep) { *sep = '\0'; CreateDirectoryA(parent, NULL); }
            }
            CreateDirectoryA(qdir, NULL);

            char qpath[MAX_PATH];
            /* Dosya adını al, timestamp ile kaydet */
            char* fname = strrchr(path, '\\');
            if (!fname) fname = strrchr(path, '/');
            snprintf(qpath, sizeof(qpath), "%s\\%lld_%s", qdir, ts, fname ? fname + 1 : "file");

            if (MoveFileExA(path, qpath, MOVEFILE_REPLACE_EXISTING)) {
                snprintf(result_msg, sizeof(result_msg),
                    "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                    "\"ts\":%lld,\"output\":\"[ACTION] Karantinaya alindi: %s -> %s\"}",
                    global_agent_id, ts, path, qpath);
            } else {
                DWORD err = GetLastError();
                snprintf(result_msg, sizeof(result_msg),
                    "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                    "\"ts\":%lld,\"output\":\"[ACTION] quarantine_file HATA (kod=%lu): %s\"}",
                    global_agent_id, ts, err, path);
            }
        }

    } else if (strncmp(action, "delete_file", 11) == 0) {
        char path[MAX_PATH] = {0};
        char* eq = strchr(action_str, '=');
        if (eq) strncpy_s(path, sizeof(path), eq + 1, _TRUNCATE);

        /* ── GÜVENLİK: Path traversal koruması ── */
        if (has_path_traversal(path)) {
            snprintf(result_msg, sizeof(result_msg),
                "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                "\"ts\":%lld,\"output\":\"[ACTION] delete_file HATA: Geçersiz dosya yolu.\"}",
                global_agent_id, ts);
        } else if (strlen(path) > 0) {
            if (DeleteFileA(path)) {
                snprintf(result_msg, sizeof(result_msg),
                    "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                    "\"ts\":%lld,\"output\":\"[ACTION] Dosya silindi: %s\"}",
                    global_agent_id, ts, path);
            } else {
                snprintf(result_msg, sizeof(result_msg),
                    "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                    "\"ts\":%lld,\"output\":\"[ACTION] delete_file HATA: %s\"}",
                    global_agent_id, ts, path);
            }
        }
    }

    if (strlen(result_msg) > 0) {
        safe_encrypt_send(soc, result_msg);
    }
}

void InitCPUTimer() {
    SYSTEM_INFO sysInfo; FILETIME fidle, fsys, fuser;
    GetSystemInfo(&sysInfo); numProcessors = sysInfo.dwNumberOfProcessors;
    FILETIME ftime; GetSystemTimeAsFileTime(&ftime); memcpy(&lastCPU, &ftime, sizeof(FILETIME));
    GetSystemTimes(&fidle, &fsys, &fuser);
    memcpy(&lastSysCPU, &fsys, sizeof(FILETIME));
    memcpy(&lastUserCPU, &fuser, sizeof(FILETIME));
    memcpy(&lastIdleCPU, &fidle, sizeof(FILETIME));
}

double GetCPULoad() {
    FILETIME ftime, fidle, fsys, fuser;
    ULARGE_INTEGER now, idle, sys, user;
    GetSystemTimeAsFileTime(&ftime); memcpy(&now, &ftime, sizeof(FILETIME));
    GetSystemTimes(&fidle, &fsys, &fuser);
    memcpy(&idle, &fidle, sizeof(FILETIME));
    memcpy(&sys,  &fsys,  sizeof(FILETIME));
    memcpy(&user, &fuser, sizeof(FILETIME));

    ULONGLONG sysDiff   = sys.QuadPart  - lastSysCPU.QuadPart;
    ULONGLONG userDiff  = user.QuadPart - lastUserCPU.QuadPart;
    ULONGLONG idleDiff  = idle.QuadPart - lastIdleCPU.QuadPart;
    ULONGLONG kernelPluUser = sysDiff + userDiff; // kernel zaten idle'i kapsar
    // KernelTime = Idle + KernelBusy, bu yuzden busy = kernelDiff - idleDiff + userDiff
    ULONGLONG busy = (sysDiff - idleDiff) + userDiff;
    double percent = (kernelPluUser > 0) ? (100.0 * (double)busy / (double)kernelPluUser) : 0.0;

    lastCPU = now; lastUserCPU = user; lastSysCPU = sys; lastIdleCPU = idle;
    return percent;
}

DWORD WINAPI ShellThread(LPVOID lpParam) {
    SOCKET soc = *(SOCKET*)lpParam;
    char recvbuf[4096];

    while (1) {
        int iResult = tls_recv_sch(soc, recvbuf, 4095);
        if (iResult > 0) {
            recvbuf[iResult] = '\0';
            recvbuf[strcspn(recvbuf, "\r\n")] = 0;

            char plain_cmd[512] = { 0 };
            decrypt_command(recvbuf, plain_cmd);

            // ACTION:: komutlarini shell'e vermeden isle
            if (strncmp(plain_cmd, "ACTION::", 8) == 0) {
                handle_action(soc, plain_cmd + 8);
                continue;
            }

            if (strncmp(plain_cmd, "cd ", 3) == 0) {
                SetCurrentDirectoryA(plain_cmd + 3);
                long long ts = GetTimestampUnix();
                char msg[512];
                snprintf(msg, sizeof(msg),
                    "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"shell_result\","
                    "\"ts\":%lld,\"output\":\"Dizin degistirildi.\"}",
                    global_agent_id, ts);
                safe_encrypt_send(soc, msg);
                continue;
            }

            /* cmd.exe /c ile sar: dir, cls, type gibi CMD ic komutlari calissin */
            char cmd_wrapped[600] = { 0 };
            snprintf(cmd_wrapped, sizeof(cmd_wrapped), "cmd.exe /c %s 2>&1", plain_cmd);
            FILE* fp = _popen(cmd_wrapped, "r");
            if (fp) {
                char path[2048] = { 0 };
                char total_output[8192] = { 0 };
                while (fgets(path, sizeof(path), fp) != NULL) {
                    if (strlen(total_output) + strlen(path) < 8000) strcat_s(total_output, sizeof(total_output), path);
                }
                _pclose(fp);
                /* Cikti bossa bile bos string dondur (komut calisti) */
                if (strlen(total_output) == 0) strcat_s(total_output, sizeof(total_output), "(cikti yok)");
                char escaped_output[16384] = { 0 };
                escape_json_string(total_output, escaped_output);

                int req_size = snprintf(NULL, 0, "{\"agent_id\":\"%s\", \"os\":\"windows\", \"type\":\"shell_result\",\"output\":\"%s\"}", global_agent_id, escaped_output);
                char* msg = (char*)malloc(req_size + 1);
                if (msg) {
                    // Linux ise os kısmını linux yapmayı unutma
                    snprintf(msg, req_size + 1, "{\"agent_id\":\"%s\", \"os\":\"windows\", \"type\":\"shell_result\",\"output\":\"%s\"}", global_agent_id, escaped_output);
                    safe_encrypt_send(soc, msg);
                    free(msg);
                }
            }
        }
        else {
            break; // Soket koptu, thread'i bitir
        }
    }
    return 0;
}

DWORD WINAPI MetricsThread(LPVOID lpParam) {
    SOCKET soc = *(SOCKET*)lpParam; MEMORYSTATUSEX mem; mem.dwLength = sizeof(MEMORYSTATUSEX); InitCPUTimer();
    while (1) {
        if (GlobalMemoryStatusEx(&mem)) {
            unsigned long long total   = mem.ullTotalPhys / 1024;
            unsigned long long free_kb = mem.ullAvailPhys / 1024;
            unsigned long long used    = total - free_kb;
            double cpuLoad = GetCPULoad();
            long long ts   = GetTimestampUnix();
            char msg[512];
            snprintf(msg, sizeof(msg),
                "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"metrics\","
                "\"ts\":%lld,\"cpu_percent\":%.1f,"
                "\"ram_total_kb\":%llu,\"ram_used_kb\":%llu,\"ram_percent\":%lu}",
                global_agent_id, ts, cpuLoad, total, used, mem.dwMemoryLoad);
            safe_encrypt_send(soc, msg);
        }
        Sleep(5000);
    }
    return 0;
}

DWORD WINAPI ProcessThread(LPVOID lpParam) {
    SOCKET soc = *(SOCKET*)lpParam;
    int initialized = 0;
    while (1) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe; pe.dwSize = sizeof(PROCESSENTRY32);
            DWORD current_pids[MAX_PROCESS_HISTORY]; int current_pid_count = 0;
            if (Process32First(snapshot, &pe)) {
                do {
                    if (current_pid_count < MAX_PROCESS_HISTORY) current_pids[current_pid_count++] = pe.th32ProcessID;
                    bool is_new = true;
                    for (int i = 0; i < previous_pid_count; i++) {
                        if (previous_pids[i] == pe.th32ProcessID) { is_new = false; break; }
                    }
                    if (is_new && initialized) {
                        char exe_path[MAX_PATH] = { 0 };
                        char username[256]      = { 0 };
                        GetProcessDetails(pe.th32ProcessID, exe_path, MAX_PATH, username, sizeof(username));

                        char esc_exe[MAX_PATH * 2]     = { 0 };
                        char esc_user[512]             = { 0 };
                        char esc_name[512]             = { 0 };
                        escape_json_string(exe_path,      esc_exe);
                        escape_json_string(username,      esc_user);
                        escape_json_string(pe.szExeFile,  esc_name);

                        long long ts = GetTimestampUnix();
                        char msg[2048];
                        snprintf(msg, sizeof(msg),
                            "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"process_new\","
                            "\"ts\":%lld,\"pname\":\"%s\",\"pid\":%lu,\"ppid\":%lu,"
                            "\"threads\":%lu,\"exe_path\":\"%s\",\"username\":\"%s\"}",
                            global_agent_id, ts, esc_name,
                            pe.th32ProcessID, pe.th32ParentProcessID, pe.cntThreads,
                            esc_exe, esc_user);
                        safe_encrypt_send(soc, msg);
                    }
                } while (Process32Next(snapshot, &pe));
            }
            CloseHandle(snapshot);
            memcpy(previous_pids, current_pids, sizeof(DWORD) * current_pid_count);
            previous_pid_count = current_pid_count;
            initialized = 1;
        }
        Sleep(10);  /* 10ms - whoami gibi cok kisa omurlu processleri kesin yakalar */
    }
    return 0;
}

DWORD WINAPI NetworkThread(LPVOID lpParam) {
    SOCKET soc = *(SOCKET*)lpParam; DWORD dwSize = 0;
    while (1) {
        NetConnection current_nets[MAX_NETWORK_HISTORY]; int current_net_count = 0;
        GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        PMIB_TCPTABLE_OWNER_PID pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
        if (pTcpTable != NULL && GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
                if (current_net_count >= MAX_NETWORK_HISTORY) break;
                if (pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
                    current_nets[current_net_count].localAddr = pTcpTable->table[i].dwLocalAddr; current_nets[current_net_count].localPort = pTcpTable->table[i].dwLocalPort;
                    current_nets[current_net_count].remoteAddr = pTcpTable->table[i].dwRemoteAddr; current_nets[current_net_count].remotePort = pTcpTable->table[i].dwRemotePort;
                    current_nets[current_net_count].owningPid = pTcpTable->table[i].dwOwningPid; current_nets[current_net_count].protocol = 1; current_net_count++;
                }
            }
        }
        if (pTcpTable) free(pTcpTable);

        for (int i = 0; i < current_net_count; i++) {
            bool is_new = true;
            for (int j = 0; j < previous_net_count; j++) {
                if (previous_nets[j].localPort == current_nets[i].localPort && previous_nets[j].remoteAddr == current_nets[i].remoteAddr &&
                    previous_nets[j].remotePort == current_nets[i].remotePort && previous_nets[j].owningPid == current_nets[i].owningPid) {
                    is_new = false; break;
                }
            }
            if (is_new) {
                char localIp[INET_ADDRSTRLEN], remoteIp[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &current_nets[i].localAddr,  localIp,  sizeof(localIp));
                inet_ntop(AF_INET, &current_nets[i].remoteAddr, remoteIp, sizeof(remoteIp));
                long long ts = GetTimestampUnix();
                char msg[1024];
                snprintf(msg, sizeof(msg),
                    "{\"agent_id\":\"%s\",\"os\":\"windows\",\"type\":\"network_new\","
                    "\"ts\":%lld,\"proto\":\"TCP\",\"pid\":%lu,"
                    "\"local_ip\":\"%s\",\"local_port\":%lu,"
                    "\"remote_ip\":\"%s\",\"remote_port\":%lu}",
                    global_agent_id, ts, current_nets[i].owningPid,
                    localIp,  ntohs((u_short)current_nets[i].localPort),
                    remoteIp, ntohs((u_short)current_nets[i].remotePort));
                safe_encrypt_send(soc, msg);
            }
        }
        memcpy(previous_nets, current_nets, sizeof(NetConnection) * current_net_count); previous_net_count = current_net_count;
        Sleep(1000);  /* 1s */
    }
    return 0;
}
void AddPersistence() {
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        char cmd[1024];
        /* Çıktıyı C:\Sentinel klasörüne logla (bu klasör quarantine_file ile aynı) */
        CreateDirectoryA("C:\\Sentinel", NULL);
        
        snprintf(cmd, sizeof(cmd), 
            "schtasks /create /f /sc onlogon /rl highest /tn \"SentinelAgent\" /tr \"\\\"%s\\\"\" > C:\\Sentinel\\schtasks.log 2>&1", exePath);
        
        system(cmd);
    }
}

int main() {
    AddPersistence();
    GetAgentID();
    InitializeCriticalSection(&send_cs);
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* FileWatcher — C2 baglantisinden bagimsiz, bir kez baslatilir */
    CreateThread(NULL, 0, FileWatchThread, NULL, 0, NULL);

    while (1) { /* OTOMATIK GERI BAGLAMA DONGUSU */
        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port   = htons(atoi(DEFAULT_PORT));
        inet_pton(AF_INET, DEFAULT_IP, &serv_addr.sin_addr);

        current_sock = socket(AF_INET, SOCK_STREAM, 0);

        if (connect(current_sock,
                    (struct sockaddr*)&serv_addr,
                    sizeof(serv_addr)) == 0) {

            /* Phase 5: Schannel TLS handshake */
            if (!tls_connect_schannel(current_sock)) {
                closesocket(current_sock);
                Sleep(5000);
                continue;
            }

            /* Phase 7: ETW kernel telemetry (Administrator gerektirir) */
            HANDLE hEtw = CreateThread(NULL, 0, ETWThread,     &current_sock, 0, NULL);
            HANDLE t1   = CreateThread(NULL, 0, ShellThread,   &current_sock, 0, NULL);
            HANDLE t2   = CreateThread(NULL, 0, MetricsThread, &current_sock, 0, NULL);
            HANDLE t3   = CreateThread(NULL, 0, ProcessThread, &current_sock, 0, NULL);
            HANDLE t4   = CreateThread(NULL, 0, NetworkThread, &current_sock, 0, NULL);

            WaitForSingleObject(t1, INFINITE); /* baglanti kopana kadar bekle */

            TerminateThread(t2, 0); TerminateThread(t3, 0);
            TerminateThread(t4, 0); TerminateThread(hEtw, 0);
            CloseHandle(t1); CloseHandle(t2); CloseHandle(t3);
            CloseHandle(t4); CloseHandle(hEtw);
            g_tls_ok = FALSE;
        }
        closesocket(current_sock);
        Sleep(5000);
    }
    return 0;
}