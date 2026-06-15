/*
    Sentinel XDR — Temel YARA Kural Seti
    =====================================
    Kapsam: PE/ELF zararlı yazılım tespiti, şüpheli davranış kalıpları,
            bilinen tehdit araçları ve packer/dropper belirtileri.

    Kullanım: Bu dosyayı yara_rules/ dizinine koyun.
              Ek kurallar için ayrı .yar dosyaları ekleyebilirsiniz.
*/

/* ── Packer ve Obfuscation ────────────────────────────────────────────────── */

rule SUSP_UPX_Packed
{
    meta:
        description = "UPX ile paketlenmiş yürütülebilir dosya"
        severity    = "medium"
        score       = 55
    strings:
        $a = "UPX0" ascii
        $b = "UPX1" ascii
        $c = "UPX!" ascii
        $d = "$Info: This file is packed with the UPX" ascii
    condition:
        2 of them
}

rule SUSP_MPRESS_Packed
{
    meta:
        description = "MPRESS packer ile paketlenmiş"
        severity    = "medium"
        score       = 55
    strings:
        $a = ".MPRESS1" ascii
        $b = ".MPRESS2" ascii
    condition:
        any of them
}

/* ── PE Yapısal Şüpheler ──────────────────────────────────────────────────── */

rule SUSP_PE_Process_Injection
{
    meta:
        description = "Process injection API kombinasyonu (hollow/inject)"
        severity    = "high"
        score       = 78
    strings:
        $va  = "VirtualAlloc"        ascii
        $wpm = "WriteProcessMemory"  ascii
        $ct  = "CreateRemoteThread" ascii
        $op  = "OpenProcess"        ascii
        $nti = "NtWriteVirtualMemory" ascii
    condition:
        uint16(0) == 0x5A4D and
        all of ($va, $wpm) and
        1 of ($ct, $op, $nti)
}

rule SUSP_PE_Embedded_PE
{
    meta:
        description = "PE dosyası içinde gömülü PE — dropper belirtisi"
        severity    = "high"
        score       = 80
    condition:
        uint16(0) == 0x5A4D and
        for any i in (1024 .. filesize - 2) : (
            uint16(i) == 0x5A4D and
            uint32(uint32(i + 60) + i) == 0x00004550
        )
}

rule SUSP_PE_No_Sections
{
    meta:
        description = "PE seksiyonu olmayan veya tek seksiyonlu dosya"
        severity    = "medium"
        score       = 50
    condition:
        uint16(0) == 0x5A4D and
        uint16(uint32(0x3C) + 6) == 0   // NumberOfSections == 0
}

rule SUSP_PE_Suspicious_Exports
{
    meta:
        description = "Reflective injection export fonksiyonu"
        severity    = "high"
        score       = 82
    strings:
        $a = "ReflectiveLoader" ascii
        $b = "ReflectiveDLLInjection" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

/* ── Credential Theft ──────────────────────────────────────────────────────── */

rule MAL_Mimikatz
{
    meta:
        description = "Mimikatz — kimlik bilgisi çalma aracı"
        severity    = "critical"
        score       = 98
    strings:
        $a = "mimikatz"           ascii nocase
        $b = "mimilib"            ascii nocase
        $c = "sekurlsa"           ascii nocase
        $d = "lsadump"            ascii nocase
        $e = "kerberos::ptt"      ascii nocase
        $f = "privilege::debug"   ascii nocase
        $g = "sekurlsa::logonpasswords" ascii nocase
    condition:
        2 of them
}

rule MAL_LaZagne
{
    meta:
        description = "LaZagne — şifre çalma aracı"
        severity    = "critical"
        score       = 95
    strings:
        $a = "lazagne"   ascii nocase
        $b = "laZagne"   ascii
        $c = "browsers"  ascii
        $d = "softwares" ascii
    condition:
        ($a or $b) and 1 of ($c, $d)
}

rule MAL_WCE
{
    meta:
        description = "Windows Credential Editor"
        severity    = "critical"
        score       = 97
    strings:
        $a = "WCE" ascii
        $b = "lsass"      ascii
        $c = "NtlmHash"   ascii nocase
        $d = "cleartext"  ascii nocase
    condition:
        $a and 1 of ($b, $c, $d)
}

/* ── C2 Frameworks ─────────────────────────────────────────────────────────── */

rule MAL_Metasploit_Meterpreter
{
    meta:
        description = "Metasploit Meterpreter payload"
        severity    = "critical"
        score       = 98
    strings:
        $a = "meterpreter"              ascii nocase
        $b = "metasploit"               ascii nocase
        $c = "ReflectiveLoader"         ascii
        $d = "stdapi_net_resolve_host"  ascii
        $e = "Meterpreter"              wide
    condition:
        any of them
}

rule MAL_CobaltStrike
{
    meta:
        description = "Cobalt Strike Beacon imzası"
        severity    = "critical"
        score       = 99
    strings:
        $s1 = "cobaltstrike"           ascii nocase
        $s2 = "beacon"                 ascii nocase
        $s3 = "CS_BEACON"             ascii
        $s4 = "%s as %s\\%s"           wide ascii
        $s5 = "IEX (New-Object Net.Webclient)" ascii nocase
        $b1 = { FC E8 89 00 00 00 60 89 E5 31 D2 }  // CS shellcode stub
        $b2 = { 4D 5A 41 52 55 48 89 E5 48 83 EC }  // CS beacon header
    condition:
        any of ($s1, $s2, $s3) or
        ($s4 and $s5) or
        any of ($b1, $b2)
}

rule MAL_Sliver_C2
{
    meta:
        description = "Sliver C2 framework"
        severity    = "critical"
        score       = 96
    strings:
        $a = "sliver" ascii nocase
        $b = "sliverd" ascii nocase
        $c = "github.com/bishopfox/sliver" ascii
    condition:
        any of them
}

/* ── Ransomware ──────────────────────────────────────────────────────────────── */

rule MAL_Ransomware_Generic
{
    meta:
        description = "Fidye yazılımı genel belirtileri"
        severity    = "critical"
        score       = 90
    strings:
        $enc1 = "Your files have been encrypted" ascii nocase
        $enc2 = "All your files"               ascii nocase
        $enc3 = ".locked"                       ascii
        $enc4 = ".encrypted"                    ascii
        $btc  = "bitcoin"                       ascii nocase
        $rns  = "ransom"                        ascii nocase
        $dec  = "decrypt"                       ascii nocase
        $cry1 = "CryptEncrypt"                  ascii
        $cry2 = "CryptGenKey"                   ascii
    condition:
        2 of ($enc1, $enc2, $enc3, $enc4, $btc, $rns, $dec) or
        all of ($cry1, $cry2)
}

rule MAL_WannaCry
{
    meta:
        description = "WannaCry / WannaCrypt fidye yazılımı"
        severity    = "critical"
        score       = 100
    strings:
        $a = "WanaCrypt0r"     ascii
        $b = "WANACRY!"       ascii
        $c = "wannacry"       ascii nocase
        $d = "m.2_115_1.key"  ascii
        $e = "taskdl.exe"     ascii
    condition:
        2 of them
}

/* ── Cryptominer ──────────────────────────────────────────────────────────── */

rule MAL_Cryptominer
{
    meta:
        description = "Kripto para madencisi"
        severity    = "high"
        score       = 85
    strings:
        $a = "stratum+tcp"      ascii nocase
        $b = "xmrig"           ascii nocase
        $c = "monero"          ascii nocase
        $d = "cryptonight"     ascii nocase
        $e = "--donate-level"  ascii
        $f = "pool.minexmr"    ascii nocase
        $g = "mining"          ascii nocase
    condition:
        2 of them
}

/* ── Backdoor / RAT ────────────────────────────────────────────────────────── */

rule MAL_Netcat_Backdoor
{
    meta:
        description = "Netcat tabanlı backdoor"
        severity    = "high"
        score       = 82
    strings:
        $a = "-e /bin/sh"    ascii
        $b = "-e cmd.exe"   ascii
        $c = "bind shell"   ascii nocase
        $d = "reverse shell" ascii nocase
        $e = "ncat"         ascii nocase
    condition:
        2 of them
}

rule MAL_Reverse_Shell
{
    meta:
        description = "Reverse shell payload kalıbı"
        severity    = "high"
        score       = 80
    strings:
        $py  = "import socket,subprocess,os;s=socket.socket"  ascii
        $bash = "/dev/tcp/"                                    ascii
        $ps  = "Net.Sockets.TCPClient"                        ascii nocase
        $php = "fsockopen"                                     ascii
    condition:
        any of them
}

/* ── PowerShell Abuse ──────────────────────────────────────────────────────── */

rule SUSP_PowerShell_Encoded
{
    meta:
        description = "Kodlanmış/gizlenmiş PowerShell komutları"
        severity    = "high"
        score       = 80
    strings:
        $enc  = "-EncodedCommand" ascii nocase
        $enc2 = "-enc "           ascii nocase
        $b64  = "FromBase64String" ascii nocase
        $iex  = "IEX("            ascii nocase
        $iex2 = "Invoke-Expression" ascii nocase
        $dl   = "DownloadString"  ascii nocase
        $dl2  = "DownloadFile"    ascii nocase
    condition:
        2 of them
}

rule SUSP_AMSI_Bypass
{
    meta:
        description = "AMSI (Antimalware Scan Interface) atlatma girişimi"
        severity    = "high"
        score       = 88
    strings:
        $a = "AmsiScanBuffer" ascii
        $b = "amsi.dll"       ascii nocase
        $c = "amsiInitFailed" ascii nocase
        $d = "AmsiOpenSession" ascii
    condition:
        2 of them
}

/* ── ELF Suspicious ────────────────────────────────────────────────────────── */

rule SUSP_ELF_Suspicious
{
    meta:
        description = "Şüpheli ELF dosyası — sistem çağrısı kalıpları"
        severity    = "medium"
        score       = 65
    strings:
        $a = "/bin/sh"      ascii
        $b = "ptrace"       ascii
        $c = "/proc/self"   ascii
        $d = "LD_PRELOAD"   ascii
        $e = "dlopen"       ascii
        $f = "setuid"       ascii
        $g = "chmod 777"    ascii
        $h = "wget "        ascii
        $i = "curl -s "    ascii
    condition:
        uint32(0) == 0x464C457F and    // ELF magic
        3 of them
}

rule MAL_ELF_Rootkit
{
    meta:
        description = "ELF rootkit belirtileri"
        severity    = "critical"
        score       = 92
    strings:
        $a = "rootkit"      ascii nocase
        $b = "hide_process" ascii nocase
        $c = "hook_syscall" ascii nocase
        $d = "lkm_init"     ascii
        $e = "sys_call_table" ascii
    condition:
        uint32(0) == 0x464C457F and 2 of them
}

/* ── Reconnaissance ────────────────────────────────────────────────────────── */

rule MAL_SharpHound
{
    meta:
        description = "SharpHound — AD keşif aracı"
        severity    = "critical"
        score       = 90
    strings:
        $a = "SharpHound" ascii
        $b = "BloodHound" ascii nocase
        $c = "DCOnly"     ascii
    condition:
        any of them
}

rule SUSP_Port_Scanner
{
    meta:
        description = "Port tarama aracı kalıpları"
        severity    = "medium"
        score       = 55
    strings:
        $a = "nmap"    ascii nocase
        $b = "masscan" ascii nocase
        $c = "SYN scan" ascii nocase
    condition:
        any of them
}
