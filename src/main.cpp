#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define NOMINMAX
#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <winioctl.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <dbt.h>

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <cstring>
#include <memory>
#include <functional>
#include <map>
#include <regex>
#include <string>
#include <thread>
#include <vector>

#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4
#endif
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

static const wchar_t* APP_NAME = L"PSD";
static const wchar_t* APP_VER = L"2.1";
static const wchar_t* UA = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) PSD/2.1";
static const wchar_t* D_ARCHIVE = L"https://darthsternie.net/ps5-firmwares/";
static const wchar_t* M_ARCHIVE = L"https://archive.midnightchannel.net/SonyPS/Firmware/index.php?cat=PS5SYS";
static const uint64_t MiB = 1024ull * 1024ull;
static const uint64_t MIN_BYTES = 512 * MiB;
static const uint64_t HEADROOM = 64 * MiB;
static const DWORD BLOCK = 4 * 1024 * 1024;
static const GUID kDiskGuid = {0x53f56307, 0xb6bf, 0x11d0, {0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}};

enum {
    WM_LOGMSG = WM_APP + 1, WM_PROG, WM_DRIVES, WM_CATALOG, WM_DONE, WM_IDENT
};
enum {
    IDC_DRIVES = 100, IDC_REFRESH, IDC_DRIVEINFO, IDC_VERSION, IDC_ARCHIVES, IDC_SITE, IDC_SOURCE, IDC_SHA,
    IDC_LOCAL, IDC_LOCALLBL, IDC_PROGRESS, IDC_STATUS, IDC_DETAIL, IDC_START, IDC_CANCEL, IDC_FORMAT,
    IDC_EJECT, IDC_CACHE, IDC_LOG
};
enum { TIMER_DEV = 1, TIMER_CLOSE = 2 };

static std::wstring W(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

static std::wstring WCP(const std::string& s, UINT cp) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(cp, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(cp, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

static std::string U(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

static std::wstring F(const wchar_t* fmt, ...) {
    wchar_t buf[4096];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, 4095, fmt, ap);
    va_end(ap);
    buf[4095] = 0;
    return buf;
}

static std::string lower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

static std::wstring wlower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

static std::wstring trim(const std::wstring& s) {
    size_t a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return {};
    size_t b = s.find_last_not_of(L" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::wstring human(uint64_t n) {
    if (n >= (1ull << 30)) return F(L"%.2f Gio", n / 1073741824.0);
    if (n >= (1ull << 20)) return F(L"%.0f Mio", n / 1048576.0);
    return F(L"%llu o", (unsigned long long)n);
}

static std::wstring win_error(DWORD e) {
    switch (e) {
    case 12002: return L"délai réseau dépassé";
    case 12007: return L"nom de serveur introuvable (pas d'Internet ou DNS)";
    case 12029: return L"connexion au serveur impossible";
    case 12030: return L"connexion interrompue";
    case 12175: return L"erreur de certificat / TLS";
    }
    wchar_t* buf = nullptr;
    HMODULE mod = (e >= 12000 && e < 13000) ? GetModuleHandleW(L"winhttp.dll") : nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS |
                  (mod ? FORMAT_MESSAGE_FROM_HMODULE : FORMAT_MESSAGE_FROM_SYSTEM);
    FormatMessageW(flags, mod, e, 0, (LPWSTR)&buf, 0, nullptr);
    std::wstring s = buf ? trim(buf) : L"";
    if (buf) LocalFree(buf);
    return F(L"%ls (code %lu)", s.empty() ? L"Erreur Windows" : s.c_str(), e);
}

struct AppError {
    std::wstring msg;
    bool fatal = true;
};
struct Cancelled {
    std::wstring msg;
};

[[noreturn]] static void fail(const std::wstring& m, bool fatal = true) { throw AppError{m, fatal}; }

static HWND g_hwnd;
static std::atomic<bool> g_cancel{false};
static std::atomic<bool> g_busy{false};
static std::atomic<bool> g_scanning{false};
static std::atomic<bool> g_catalog_loading{false};
static HINTERNET g_session;
static std::wstring g_cache, g_exe_dir;

static void check_cancel() {
    if (g_cancel) throw Cancelled{L"Opération annulée. Le téléchargement partiel est conservé."};
}

static void post_log(const std::wstring& s) { PostMessageW(g_hwnd, WM_LOGMSG, 0, (LPARAM) new std::wstring(s)); }

struct Prog {
    std::wstring phase, detail;
    uint64_t cur = 0, total = 0;
};

static void post_prog(const std::wstring& phase, uint64_t cur, uint64_t total, const std::wstring& detail) {
    PostMessageW(g_hwnd, WM_PROG, 0, (LPARAM) new Prog{phase, detail, cur, total});
}

struct Meter {
    std::wstring phase;
    uint64_t total, last_n;
    ULONGLONG last_t, last_post = 0;
    double rate = 0;
    Meter(std::wstring p, uint64_t t, uint64_t base = 0) : phase(std::move(p)), total(t), last_n(base), last_t(GetTickCount64()) {}
    void tick(uint64_t n, bool force = false) {
        ULONGLONG now = GetTickCount64();
        if (!force && now - last_post < 200) return;
        double dt = (now - last_t) / 1000.0;
        if (dt > 0.05) {
            double inst = (double)(n - last_n) / dt;
            rate = rate <= 0 ? inst : rate * 0.75 + inst * 0.25;
            last_t = now;
            last_n = n;
        }
        last_post = now;
        std::wstring d = human(n) + L" / " + (total ? human(total) : L"?");
        if (rate > 0) {
            d += F(L"   ·   %.1f Mio/s", rate / MiB);
            if (total > n) {
                uint64_t s = (uint64_t)((total - n) / rate);
                d += F(L"   ·   reste %llu:%02llu", (unsigned long long)(s / 60), (unsigned long long)(s % 60));
            }
        }
        post_prog(phase, n, total, d);
    }
};

struct Firmware {
    std::wstring version;
    std::string sha256, md5;
    uint64_t size = 0;
    std::wstring direct, mega;
};
using Catalog = std::map<std::wstring, Firmware>;

static bool is_hex(const std::string& s, size_t n) {
    if (s.size() != n) return false;
    for (char c : s)
        if (!isxdigit((unsigned char)c)) return false;
    return true;
}

static std::vector<int> version_key(const std::wstring& v) {
    std::vector<int> k;
    size_t p = 0;
    while (p <= v.size()) {
        size_t q = v.find(L'.', p);
        if (q == std::wstring::npos) q = v.size();
        k.push_back(_wtoi(v.substr(p, q - p).c_str()));
        p = q + 1;
    }
    return k;
}

static std::wstring normalize_version(const std::string& s) {
    int a = 0, b = 0, c = 0;
    if (sscanf(s.c_str(), "%d.%d.%d", &a, &b, &c) < 2) return {};
    if (a < 1 || a > 40 || b < 0 || b > 99 || c < 0 || c > 99) return {};
    return F(L"%02d.%02d.%02d", a, b, c);
}

static Catalog builtin_catalog() {
    Catalog c;
    auto add = [&](const wchar_t* v, const char* sha, const char* md5, uint64_t size, const wchar_t* direct) {
        Firmware f;
        f.version = v;
        f.sha256 = sha;
        f.md5 = md5;
        f.size = size;
        f.direct = direct;
        c[v] = f;
    };
    add(L"13.60.00", "767a94eac034d33907a6ff57af05bc30ce057258ad1cf4b5ffb75d5e21112561", "06a74efce009503170b7add7fecfeb36",
        1247471104ull,
        L"https://archive.midnightchannel.net/SonyPS/Firmware/download/767a94eac034d33907a6ff57af05bc30ce057258ad1cf4b5ffb75d5e21112561/PS5SYS_CRC%5B1968AB46%5D_PS5UPDATE.PUP");
    add(L"14.00.00", "1eb4b18451e0f064fc23b5bd4c95cae7f6489f9ad1148b5dfb0d66452a108ebc", "6e100a2f04a0e4c7b0418c72b4f7e1a9", 0, L"");
    add(L"14.10.00", "c17384946df6e5c85b2d72cbeee2057b165bf90279d9e2a86d527d0778cdaaf6", "f7853a0fa97a9a7828ac548798012782", 0, L"");
    add(L"14.22.00", "b0d5818d5ce26e2537d1e2febaebd9a3bef1bb1cf8e9898ddf099773706a810b", "", 0, L"");
    return c;
}

static bool allowed_download(const std::wstring& url) {
    std::wstring l = wlower(url);
    const std::wstring pre = L"https://archive.midnightchannel.net/sonyps/firmware/download/";
    if (l.compare(0, pre.size(), pre) != 0) return false;
    size_t q = l.find_first_of(L"?#");
    std::wstring path = l.substr(0, q);
    return path.size() > 4 && path.compare(path.size() - 4, 4, L".pup") == 0;
}

static std::wstring url_host(const std::wstring& url) {
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof uc;
    wchar_t host[256]{};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) return {};
    return wlower(host);
}

static void http_init() {
    g_session = WinHttpOpen(UA, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_session) g_session = WinHttpOpen(UA, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_session) return;
    DWORD p = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    if (!WinHttpSetOption(g_session, WINHTTP_OPTION_SECURE_PROTOCOLS, &p, sizeof p)) {
        p = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(g_session, WINHTTP_OPTION_SECURE_PROTOCOLS, &p, sizeof p);
    }
    DWORD redir = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    WinHttpSetOption(g_session, WINHTTP_OPTION_REDIRECT_POLICY, &redir, sizeof redir);
    WinHttpSetTimeouts(g_session, 15000, 15000, 30000, 35000);
}

struct Req {
    HINTERNET c = nullptr, r = nullptr;
    DWORD status = 0;
    Req() = default;
    Req(const Req&) = delete;
    ~Req() {
        if (r) WinHttpCloseHandle(r);
        if (c) WinHttpCloseHandle(c);
    }
    std::wstring header(DWORD q) {
        DWORD len = 0;
        WinHttpQueryHeaders(r, q, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &len, WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !len) return {};
        std::wstring s(len / sizeof(wchar_t) + 1, 0);
        if (!WinHttpQueryHeaders(r, q, WINHTTP_HEADER_NAME_BY_INDEX, s.data(), &len, WINHTTP_NO_HEADER_INDEX)) return {};
        s.resize(len / sizeof(wchar_t));
        return s;
    }
    std::wstring final_url() {
        DWORD len = 0;
        WinHttpQueryOption(r, WINHTTP_OPTION_URL, nullptr, &len);
        if (!len) return {};
        std::wstring s(len / sizeof(wchar_t) + 1, 0);
        if (!WinHttpQueryOption(r, WINHTTP_OPTION_URL, s.data(), &len)) return {};
        s.resize(wcslen(s.c_str()));
        return s;
    }
};

static void http_open(Req& q, const std::wstring& url, const std::wstring& headers) {
    if (!g_session) fail(L"WinHTTP indisponible sur ce PC");
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof uc;
    std::vector<wchar_t> host(512), path(8192), extra(8192);
    uc.lpszHostName = host.data();
    uc.dwHostNameLength = 512;
    uc.lpszUrlPath = path.data();
    uc.dwUrlPathLength = 8192;
    uc.lpszExtraInfo = extra.data();
    uc.dwExtraInfoLength = 8192;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) fail(L"Adresse invalide : " + url);
    if (uc.nScheme != INTERNET_SCHEME_HTTPS) fail(L"HTTPS obligatoire : " + url);
    q.c = WinHttpConnect(g_session, host.data(), uc.nPort, 0);
    if (!q.c) fail(L"Connexion impossible : " + win_error(GetLastError()), false);
    std::wstring object = std::wstring(path.data()) + extra.data();
    q.r = WinHttpOpenRequest(q.c, L"GET", object.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!q.r) fail(L"Requête impossible : " + win_error(GetLastError()), false);
    BOOL ok = headers.empty()
                  ? WinHttpSendRequest(q.r, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
                  : WinHttpSendRequest(q.r, headers.c_str(), (DWORD)headers.size(), WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok || !WinHttpReceiveResponse(q.r, nullptr)) fail(L"Réseau : " + win_error(GetLastError()), false);
    DWORD st = 0, sz = sizeof st;
    WinHttpQueryHeaders(q.r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &st, &sz, WINHTTP_NO_HEADER_INDEX);
    q.status = st;
    std::wstring fin = wlower(q.final_url());
    if (!fin.empty() && fin.rfind(L"https://", 0) != 0) fail(L"Redirection non sécurisée refusée");
}

static std::string http_text(const std::wstring& url) {
    Req q;
    http_open(q, url, L"Accept: text/html,application/xhtml+xml\r\n");
    if (q.status != 200) fail(F(L"HTTP %lu", q.status));
    std::string body;
    std::vector<char> buf(65536);
    while (body.size() < 6 * MiB) {
        DWORD got = 0;
        if (!WinHttpReadData(q.r, buf.data(), (DWORD)buf.size(), &got)) fail(L"Lecture réseau : " + win_error(GetLastError()));
        if (!got) break;
        body.append(buf.data(), got);
    }
    return body;
}

static std::string utf8_cp(unsigned long cp) {
    std::string o;
    if (cp < 0x80) o += (char)cp;
    else if (cp < 0x800) { o += (char)(0xC0 | (cp >> 6)); o += (char)(0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) { o += (char)(0xE0 | (cp >> 12)); o += (char)(0x80 | ((cp >> 6) & 0x3F)); o += (char)(0x80 | (cp & 0x3F)); }
    else if (cp < 0x110000) { o += (char)(0xF0 | (cp >> 18)); o += (char)(0x80 | ((cp >> 12) & 0x3F)); o += (char)(0x80 | ((cp >> 6) & 0x3F)); o += (char)(0x80 | (cp & 0x3F)); }
    return o;
}

static std::string decode_entities(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        if (s[i] == '&') {
            size_t e = s.find(';', i);
            if (e != std::string::npos && e - i <= 10 && e > i + 1) {
                std::string ent = s.substr(i + 1, e - i - 1), rep;
                bool ok = true;
                if (ent == "amp") rep = "&";
                else if (ent == "lt") rep = "<";
                else if (ent == "gt") rep = ">";
                else if (ent == "quot") rep = "\"";
                else if (ent == "apos") rep = "'";
                else if (ent == "nbsp") rep = " ";
                else if (ent[0] == '#') {
                    unsigned long cp = (ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X')) ? strtoul(ent.c_str() + 2, nullptr, 16)
                                                                                               : strtoul(ent.c_str() + 1, nullptr, 10);
                    rep = cp == 0xA0 ? " " : utf8_cp(cp);
                } else ok = false;
                if (ok) {
                    o += rep;
                    i = e + 1;
                    continue;
                }
            }
        }
        o += s[i++];
    }
    return o;
}

static std::string collapse(const std::string& s) {
    std::string o;
    bool sp = false;
    for (unsigned char c : s) {
        if (isspace(c)) { sp = true; continue; }
        if (sp && !o.empty()) o += ' ';
        sp = false;
        o += (char)c;
    }
    return o;
}

struct Cell {
    std::string text;
    std::vector<std::string> links;
};
struct Row {
    std::string section;
    std::vector<Cell> cells;
};

static std::vector<Row> parse_tables(const std::string& h) {
    static const std::regex href_re(R"re(href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))re", std::regex::icase);
    std::vector<Row> rows;
    std::string lh = lower(h), section, heading, headbuf, celltext;
    bool in_tr = false, in_cell = false;
    std::vector<std::string> links;
    std::vector<Cell> cells;
    auto end_cell = [&] {
        cells.push_back({collapse(decode_entities(celltext)), links});
        in_cell = false;
    };
    auto end_row = [&] {
        if (in_cell) end_cell();
        if (!cells.empty()) rows.push_back({section, cells});
        cells.clear();
        in_tr = false;
    };
    size_t i = 0, n = h.size();
    while (i < n) {
        if (h[i] == '<') {
            if (h.compare(i, 4, "<!--") == 0) {
                size_t e = h.find("-->", i + 4);
                i = e == std::string::npos ? n : e + 3;
                continue;
            }
            size_t e = h.find('>', i);
            if (e == std::string::npos) break;
            std::string tag = h.substr(i + 1, e - i - 1);
            i = e + 1;
            bool close = !tag.empty() && tag[0] == '/';
            size_t p = close ? 1 : 0, q = p;
            while (q < tag.size() && isalnum((unsigned char)tag[q])) q++;
            std::string name = lower(tag.substr(p, q - p));
            if (!close && (name == "script" || name == "style")) {
                size_t e2 = lh.find("</" + name, i);
                i = e2 == std::string::npos ? n : e2;
                continue;
            }
            bool hx = name.size() == 2 && name[0] == 'h' && name[1] >= '2' && name[1] <= '5';
            if (!close) {
                if (hx) { heading = name; headbuf.clear(); }
                else if (name == "tr") { if (in_tr) end_row(); in_tr = true; cells.clear(); }
                else if ((name == "td" || name == "th") && in_tr) {
                    if (in_cell) end_cell();
                    in_cell = true;
                    celltext.clear();
                    links.clear();
                } else if (name == "a" && in_cell) {
                    std::smatch m;
                    if (std::regex_search(tag, m, href_re)) {
                        std::string v = m[1].matched ? m[1].str() : m[2].matched ? m[2].str() : m[3].str();
                        links.push_back(decode_entities(v));
                    }
                } else if (name == "br" && in_cell) celltext += ' ';
            } else {
                if (!heading.empty() && name == heading) {
                    std::string s = lower(headbuf);
                    if (s.find("recovery") != std::string::npos) section = "recovery";
                    else if (s.find("official") != std::string::npos || s.find("system") != std::string::npos || s.find("firmware") != std::string::npos) section = "system";
                    heading.clear();
                } else if ((name == "td" || name == "th") && in_cell) end_cell();
                else if (name == "tr" && in_tr) end_row();
                else if (name == "table" && in_tr) end_row();
            }
            continue;
        }
        size_t e = h.find('<', i);
        if (e == std::string::npos) e = n;
        if (!heading.empty()) headbuf.append(h, i, e - i);
        if (in_cell) celltext.append(h, i, e - i);
        i = e;
    }
    if (in_tr) end_row();
    return rows;
}

static std::wstring url_join(const std::wstring& base, const std::string& link8) {
    std::wstring link = W(link8);
    if (link.rfind(L"http://", 0) == 0 || link.rfind(L"https://", 0) == 0) return link;
    if (link.rfind(L"//", 0) == 0) return L"https:" + link;
    size_t sch = base.find(L"://");
    size_t host_end = base.find(L'/', sch + 3);
    std::wstring origin = base.substr(0, host_end);
    if (!link.empty() && link[0] == L'/') return origin + link;
    std::wstring nq = base.substr(0, base.find_first_of(L"?#"));
    if (!link.empty() && link[0] == L'?') return nq + link;
    if (!link.empty() && link[0] == L'#') return base + link;
    return nq.substr(0, nq.rfind(L'/') + 1) + link;
}

static std::string find_hex(const std::vector<Cell>& cells, size_t len) {
    std::regex re("(?:^|[^0-9a-fA-F])([0-9a-fA-F]{" + std::to_string(len) + "})(?:[^0-9a-fA-F]|$)");
    for (auto& c : cells) {
        std::smatch m;
        if (std::regex_search(c.text, m, re)) return lower(m[1].str());
    }
    return {};
}

static std::wstring find_version(const std::vector<Cell>& cells, const std::string& joined) {
    static const std::regex cell_re(R"(^\s*v?(\d{1,2}\.\d{2}(?:\.\d{2})?)\s*$)", std::regex::icase);
    static const std::regex text_re(R"((?:firmware|system\s*software|version|ver\.?|\bv)\s*:?\s*(\d{1,2}\.\d{2}(?:\.\d{2})?)(?![\d.]))", std::regex::icase);
    std::smatch m;
    for (auto& c : cells)
        if (std::regex_match(c.text, m, cell_re)) return normalize_version(m[1].str());
    if (std::regex_search(joined, m, text_re)) return normalize_version(m[1].str());
    return {};
}

static Catalog scan_catalog() {
    Catalog out = builtin_catalog();
    try {
        auto rows = parse_tables(http_text(D_ARCHIVE));
        int count = 0;
        for (auto& r : rows) {
            if (r.section == "recovery") continue;
            std::string joined;
            for (auto& c : r.cells) joined += c.text + " ";
            std::string lj = lower(joined);
            if (lj.find("recovery") != std::string::npos || lj.find("sys_ex") != std::string::npos) continue;
            std::wstring v = find_version(r.cells, joined);
            if (v.empty()) continue;
            Firmware& f = out[v];
            f.version = v;
            std::string md5 = find_hex(r.cells, 32);
            if (!md5.empty()) {
                if (!f.md5.empty() && f.md5 != md5) post_log(L"MD5 contradictoire pour " + v + L" : valeur intégrée conservée");
                else f.md5 = md5;
            }
            for (auto& c : r.cells)
                for (auto& l : c.links) {
                    std::wstring u = url_join(D_ARCHIVE, l);
                    if (url_host(u) == L"mega.nz" && f.mega.empty()) f.mega = u;
                }
            count++;
        }
        post_log(F(L"Darthsternie : %d version(s) recensée(s) (liens MEGA)", count));
    } catch (AppError& e) {
        post_log(L"Darthsternie inaccessible : " + e.msg);
    } catch (std::exception& e) {
        post_log(L"Darthsternie illisible : " + W(e.what()));
    }
    try {
        auto rows = parse_tables(http_text(M_ARCHIVE));
        int count = 0;
        for (auto& r : rows) {
            if (r.section == "recovery") continue;
            std::string joined;
            for (auto& c : r.cells) joined += c.text + " ";
            std::string lj = lower(joined);
            if (lj.find("recovery") != std::string::npos || lj.find("sys_ex") != std::string::npos || lj.find("disc") != std::string::npos) continue;
            std::wstring v = find_version(r.cells, joined);
            if (v.empty()) continue;
            std::string sha = find_hex(r.cells, 64);
            auto it = out.find(v);
            if (!sha.empty() && it != out.end() && !it->second.sha256.empty() && it->second.sha256 != sha) {
                post_log(L"SHA-256 CONTRADICTOIRE pour " + v + L" : entrée distante ignorée");
                continue;
            }
            Firmware& f = out[v];
            f.version = v;
            if (!sha.empty()) f.sha256 = sha;
            for (auto& c : r.cells)
                for (auto& l : c.links) {
                    std::wstring u = url_join(M_ARCHIVE, l);
                    if (allowed_download(u)) { f.direct = u; break; }
                }
            count++;
        }
        post_log(F(L"Midnight Channel : %d version(s) recensée(s) (SHA-256 + HTTPS)", count));
    } catch (AppError& e) {
        post_log(L"Midnight Channel inaccessible : " + e.msg);
    } catch (std::exception& e) {
        post_log(L"Midnight Channel illisible : " + W(e.what()));
    }
    std::wstring jpath = g_exe_dir + L"\\sha256_references.json";
    HANDLE h = CreateFileW(jpath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        std::string js(256 * 1024, 0);
        DWORD got = 0;
        ReadFile(h, js.data(), (DWORD)js.size(), &got, nullptr);
        CloseHandle(h);
        js.resize(got);
        static const std::regex re(R"rx("(\d{1,2}\.\d{2}(?:\.\d{2})?)"\s*:\s*\{[^}]*?"sha256"\s*:\s*"([0-9a-fA-F]{64})")rx");
        int added = 0;
        for (auto it = std::sregex_iterator(js.begin(), js.end(), re); it != std::sregex_iterator(); ++it) {
            std::wstring v = normalize_version((*it)[1].str());
            std::string sha = lower((*it)[2].str());
            if (v.empty()) continue;
            Firmware& f = out[v];
            f.version = v;
            if (!f.sha256.empty() && f.sha256 != sha) post_log(L"Conflit SHA-256 sur " + v + L" (JSON perso) : référence connue conservée");
            else { f.sha256 = sha; added++; }
        }
        post_log(F(L"sha256_references.json : %d empreinte(s) chargée(s)", added));
    }
    return out;
}

struct Hasher {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    DWORD len = 0;
    explicit Hasher(LPCWSTR id) {
        DWORD cb = 0;
        if (BCryptOpenAlgorithmProvider(&alg, id, nullptr, 0) != 0 ||
            BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&len, sizeof len, &cb, 0) != 0 ||
            BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) != 0)
            fail(L"Initialisation BCrypt impossible");
    }
    Hasher(const Hasher&) = delete;
    ~Hasher() {
        if (h) BCryptDestroyHash(h);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    }
    void update(const void* p, size_t n) { BCryptHashData(h, (PUCHAR)p, (ULONG)n, 0); }
    std::string hex() {
        std::vector<UCHAR> o(len);
        BCryptFinishHash(h, o.data(), len, 0);
        static const char* d = "0123456789abcdef";
        std::string s;
        for (UCHAR b : o) { s += d[b >> 4]; s += d[b & 15]; }
        return s;
    }
};

struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE x) : h(x) {}
    Handle(const Handle&) = delete;
    ~Handle() { close(); }
    void close() {
        if (h != INVALID_HANDLE_VALUE && h) CloseHandle(h);
        h = INVALID_HANDLE_VALUE;
    }
    bool ok() const { return h != INVALID_HANDLE_VALUE && h; }
};

struct AlignedBuf {
    BYTE* p;
    explicit AlignedBuf(size_t n) : p((BYTE*)VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
        if (!p) fail(L"Mémoire insuffisante");
    }
    AlignedBuf(const AlignedBuf&) = delete;
    ~AlignedBuf() { VirtualFree(p, 0, MEM_RELEASE); }
};

static bool file_exists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static uint64_t file_size(const std::wstring& p) {
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &d)) return 0;
    return ((uint64_t)d.nFileSizeHigh << 32) | d.nFileSizeLow;
}

static void make_dirs(const std::wstring& p) { SHCreateDirectoryExW(nullptr, p.c_str(), nullptr); }

static void check_header(const std::wstring& p) {
    Handle h(CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!h.ok()) fail(L"Impossible d'ouvrir " + p + L" : " + win_error(GetLastError()));
    char head[4]{};
    DWORD got = 0;
    ReadFile(h.h, head, 4, &got, nullptr);
    if (got != 4 || memcmp(head, "SLB2", 4) != 0) fail(L"En-tête SLB2 absent : ce n'est pas un PUP PS5 valide (ou fichier corrompu)");
}

static std::string hash_file(const std::wstring& path, bool unbuffered, const std::wstring& phase, std::string* md5out = nullptr) {
    DWORD flags = FILE_FLAG_SEQUENTIAL_SCAN | (unbuffered ? FILE_FLAG_NO_BUFFERING : 0);
    Handle h(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, flags, nullptr));
    if (!h.ok()) fail(L"Lecture impossible : " + path + L"\n" + win_error(GetLastError()));
    uint64_t total = file_size(path), n = 0;
    Hasher sha(BCRYPT_SHA256_ALGORITHM);
    std::unique_ptr<Hasher> md5(md5out ? new Hasher(BCRYPT_MD5_ALGORITHM) : nullptr);
    AlignedBuf buf(BLOCK);
    Meter m(phase, total);
    for (;;) {
        check_cancel();
        DWORD got = 0;
        if (!ReadFile(h.h, buf.p, BLOCK, &got, nullptr)) fail(L"Erreur de lecture : " + win_error(GetLastError()));
        if (!got) break;
        sha.update(buf.p, got);
        if (md5) md5->update(buf.p, got);
        n += got;
        m.tick(n);
    }
    m.tick(n, true);
    if (n != total) fail(L"Lecture incomplète du fichier");
    if (md5out) *md5out = md5->hex();
    return sha.hex();
}

struct Drive {
    wchar_t letter = 0;
    std::wstring label, fs, model, id;
    uint64_t size = 0, free = 0;
    DWORD disk = 0;
    bool removable = false;
    std::wstring root() const { return std::wstring{letter, L':', L'\\'}; }
    bool fs_ok() const {
        std::wstring l = wlower(fs);
        return l == L"fat32" || l == L"exfat";
    }
};

static std::vector<Drive> list_usb() {
    std::vector<Drive> out;
    wchar_t windir[MAX_PATH]{};
    GetWindowsDirectoryW(windir, MAX_PATH);
    wchar_t sys = (wchar_t)towupper(windir[0]);
    DWORD mask = GetLogicalDrives();
    for (int i = 2; i < 26; i++) {
        if (!(mask & (1u << i))) continue;
        wchar_t L = (wchar_t)(L'A' + i);
        if (L == sys) continue;
        std::wstring root{L, L':', L'\\'};
        UINT t = GetDriveTypeW(root.c_str());
        if (t != DRIVE_REMOVABLE && t != DRIVE_FIXED) continue;
        std::wstring dev = std::wstring(L"\\\\.\\") + L + L':';
        HANDLE h = CreateFileW(dev.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        STORAGE_PROPERTY_QUERY q{};
        q.PropertyId = StorageDeviceProperty;
        q.QueryType = PropertyStandardQuery;
        alignas(8) BYTE buf[4096]{};
        DWORD got = 0;
        bool usb = false;
        std::string vendor, product, serial;
        if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, buf, sizeof buf - 1, &got, nullptr)) {
            auto* d = (STORAGE_DEVICE_DESCRIPTOR*)buf;
            usb = d->BusType == BusTypeUsb;
            auto str = [&](DWORD off) { return (off && off < got) ? std::string((char*)buf + off) : std::string(); };
            vendor = str(d->VendorIdOffset);
            product = str(d->ProductIdOffset);
            serial = str(d->SerialNumberOffset);
        }
        STORAGE_DEVICE_NUMBER sdn{};
        bool hasnum = DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &sdn, sizeof sdn, &got, nullptr);
        GET_LENGTH_INFORMATION li{};
        bool haslen = DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0, &li, sizeof li, &got, nullptr);
        CloseHandle(h);
        if (!usb || !hasnum) continue;
        Drive d;
        d.letter = L;
        d.disk = sdn.DeviceNumber;
        d.removable = t == DRIVE_REMOVABLE;
        d.model = trim(trim(WCP(vendor, CP_ACP)) + L" " + trim(WCP(product, CP_ACP)));
        d.id = trim(WCP(serial, CP_ACP)) + L"#" + std::to_wstring(d.disk) + L"#" + d.model;
        wchar_t label[MAX_PATH + 1]{}, fsn[64]{};
        if (GetVolumeInformationW(root.c_str(), label, MAX_PATH + 1, nullptr, nullptr, nullptr, fsn, 64)) {
            d.label = label;
            d.fs = fsn;
        } else d.fs = L"RAW";
        ULARGE_INTEGER fa{}, tot{}, fr{};
        if (GetDiskFreeSpaceExW(root.c_str(), &fa, &tot, &fr)) {
            d.size = tot.QuadPart;
            d.free = fa.QuadPart;
        } else if (haslen) d.size = (uint64_t)li.Length.QuadPart;
        out.push_back(d);
    }
    return out;
}

static Drive recheck_drive(const Drive& d) {
    for (auto& x : list_usb())
        if (x.letter == d.letter && x.id == d.id) return x;
    fail(L"La clé USB a été débranchée ou remplacée depuis la sélection. Actualise la liste.");
}

static std::wstring megacmd() {
    const wchar_t* names[] = {L"mega-get.bat", L"mega-get.cmd", L"mega-get.exe"};
    wchar_t buf[MAX_PATH];
    for (auto n : names)
        if (SearchPathW(nullptr, n, nullptr, MAX_PATH, buf, nullptr)) return buf;
    wchar_t la[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", la, MAX_PATH)) {
        std::wstring p = std::wstring(la) + L"\\MEGAcmd\\mega-get.bat";
        if (file_exists(p)) return p;
    }
    return {};
}

static void largest_file(const std::wstring& dir, std::wstring& best, uint64_t& best_size) {
    WIN32_FIND_DATAW fd;
    HANDLE f = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (f == INVALID_HANDLE_VALUE) return;
    do {
        std::wstring n = fd.cFileName;
        if (n == L"." || n == L"..") continue;
        std::wstring full = dir + L"\\" + n;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) largest_file(full, best, best_size);
        else {
            uint64_t s = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (s > best_size) { best_size = s; best = full; }
        }
    } while (FindNextFileW(f, &fd));
    FindClose(f);
}

static void delete_tree(const std::wstring& dir) {
    std::wstring from = dir + L'\0';
    SHFILEOPSTRUCTW op{};
    op.wFunc = FO_DELETE;
    op.pFrom = from.c_str();
    op.fFlags = FOF_NO_UI;
    SHFileOperationW(&op);
}

static void download_mega(const Firmware& fw, const std::wstring& dest) {
    if (url_host(fw.mega) != L"mega.nz" || fw.mega.find(L'#') == std::wstring::npos) fail(L"Lien MEGA incomplet (clé de partage absente)");
    std::wstring exe = megacmd();
    if (exe.empty()) fail(L"MEGAcmd n'est pas installé (https://mega.nz/cmd)");
    std::wstring dir = dest.substr(0, dest.rfind(L'\\')) + L"\\mega";
    delete_tree(dir);
    make_dirs(dir);
    post_log(L"Téléchargement MEGA via MEGAcmd…");
    std::wstring cmd = L"cmd.exe /d /c \"\"" + exe + L"\" \"" + fw.mega + L"\" \"" + dir + L"\"\"";
    STARTUPINFOW si{};
    si.cb = sizeof si;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        fail(L"Lancement de MEGAcmd impossible : " + win_error(GetLastError()));
    CloseHandle(pi.hThread);
    Handle proc(pi.hProcess);
    Meter m(L"Téléchargement MEGA", fw.size);
    while (WaitForSingleObject(proc.h, 400) == WAIT_TIMEOUT) {
        if (g_cancel) {
            TerminateProcess(proc.h, 1);
            throw Cancelled{L"Arrêt demandé. MEGAcmd peut poursuivre le transfert en arrière-plan."};
        }
        std::wstring best;
        uint64_t bs = 0;
        largest_file(dir, best, bs);
        m.tick(bs);
    }
    DWORD code = 0;
    GetExitCodeProcess(proc.h, &code);
    if (code) fail(F(L"MEGAcmd a échoué (code %lu)", code));
    std::wstring best;
    uint64_t bs = 0;
    largest_file(dir, best, bs);
    if (best.empty() || bs < MIN_BYTES) fail(L"Aucun PUP complet trouvé après MEGAcmd");
    if (!MoveFileExW(best.c_str(), dest.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
        fail(L"Déplacement du PUP MEGA impossible : " + win_error(GetLastError()));
    delete_tree(dir);
}

static std::vector<std::wstring> read_lines(const std::wstring& p) {
    std::vector<std::wstring> out;
    Handle h(CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!h.ok()) return out;
    std::string s(16384, 0);
    DWORD got = 0;
    ReadFile(h.h, s.data(), (DWORD)s.size(), &got, nullptr);
    s.resize(got);
    std::wstring w = W(s);
    size_t a = 0;
    while (a <= w.size()) {
        size_t b = w.find(L'\n', a);
        if (b == std::wstring::npos) b = w.size();
        out.push_back(w.substr(a, b - a));
        a = b + 1;
    }
    return out;
}

static void write_lines(const std::wstring& p, const std::vector<std::wstring>& lines) {
    std::wstring w;
    for (auto& l : lines) w += l + L"\n";
    std::string s = U(w);
    std::wstring tmp = p + L".new";
    {
        Handle h(CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr));
        if (!h.ok()) return;
        DWORD wr = 0;
        WriteFile(h.h, s.data(), (DWORD)s.size(), &wr, nullptr);
    }
    MoveFileExW(tmp.c_str(), p.c_str(), MOVEFILE_REPLACE_EXISTING);
}

static void sleep_cancellable(int seconds) {
    for (int i = 0; i < seconds * 10; i++) {
        check_cancel();
        Sleep(100);
    }
}

static void download_http(const Firmware& fw, const std::wstring& dest) {
    if (!allowed_download(fw.direct)) fail(L"Adresse de téléchargement non autorisée");
    std::wstring part = dest + L".part", meta = dest + L".part.meta";
    AppError last{L"inconnue"};
    for (int attempt = 1; attempt <= 8; attempt++) {
        check_cancel();
        try {
            uint64_t existing = file_exists(part) ? file_size(part) : 0;
            if (fw.size && existing > fw.size) {
                DeleteFileW(part.c_str());
                existing = 0;
            }
            if (fw.size && existing == fw.size) {
                if (!MoveFileExW(part.c_str(), dest.c_str(), MOVEFILE_REPLACE_EXISTING)) fail(L"Renommage impossible : " + win_error(GetLastError()));
                DeleteFileW(meta.c_str());
                return;
            }
            auto info = read_lines(meta);
            if (existing && (info.size() < 2 || info[0] != fw.direct || info[1] != W(fw.sha256))) {
                post_log(L"Reprise invalide (source différente) : téléchargement repris à zéro");
                DeleteFileW(part.c_str());
                existing = 0;
            }
            std::wstring hdr = L"Accept: application/octet-stream\r\nReferer: " + std::wstring(M_ARCHIVE) + L"\r\n";
            if (existing) {
                hdr += F(L"Range: bytes=%llu-\r\n", (unsigned long long)existing);
                if (info.size() > 2 && !info[2].empty()) hdr += L"If-Range: " + info[2] + L"\r\n";
                else if (info.size() > 3 && !info[3].empty()) hdr += L"If-Range: " + info[3] + L"\r\n";
            }
            Req q;
            http_open(q, fw.direct, hdr);
            DWORD code = q.status;
            if (code == 400 || code == 401 || code == 403 || code == 404 || code == 410 || code == 451)
                fail(F(L"Archive inaccessible (HTTP %lu). Télécharge le PUP via MEGA dans le navigateur puis glisse-le dans la fenêtre.", code));
            if (code == 416) {
                DeleteFileW(part.c_str());
                fail(L"Plage HTTP refusée : reprise à zéro", false);
            }
            if (wlower(q.header(WINHTTP_QUERY_CONTENT_TYPE)).find(L"text/html") != std::wstring::npos)
                fail(L"Le serveur renvoie une page HTML au lieu du firmware (protection anti-robot ?). Télécharge-le dans le navigateur puis glisse-le dans la fenêtre.");
            bool append = false;
            uint64_t offset = 0;
            if (existing && code == 206) {
                std::string cr = U(q.header(WINHTTP_QUERY_CONTENT_RANGE));
                unsigned long long a = 0, b = 0, t = 0;
                int k = sscanf(cr.c_str(), "bytes %llu-%llu/%llu", &a, &b, &t);
                if (k < 2 || a != existing) fail(L"Réponse HTTP Range incohérente", false);
                if (k == 3 && fw.size && t != fw.size) fail(L"Taille distante différente du firmware attendu");
                append = true;
                offset = existing;
            } else if (code != 200) {
                fail(F(L"Réponse HTTP inattendue : %lu", code), false);
            } else if (existing) {
                post_log(L"Le serveur ne gère pas la reprise : téléchargement repris à zéro");
            }
            uint64_t length = _wcstoui64(q.header(WINHTTP_QUERY_CONTENT_LENGTH).c_str(), nullptr, 10);
            uint64_t total = fw.size ? fw.size : (length ? offset + length : 0);
            if (length && fw.size && offset + length != fw.size) fail(L"La longueur HTTP ne correspond pas au firmware attendu");
            if (total) {
                ULARGE_INTEGER fa{};
                if (GetDiskFreeSpaceExW(g_cache.c_str(), &fa, nullptr, nullptr) && fa.QuadPart < total - offset + HEADROOM)
                    fail(L"Espace disque insuffisant sur le PC : il faut " + human(total - offset + HEADROOM));
            }
            write_lines(meta, {fw.direct, W(fw.sha256), q.header(WINHTTP_QUERY_ETAG), q.header(WINHTTP_QUERY_LAST_MODIFIED)});
            Handle out(CreateFileW(part.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, append ? OPEN_ALWAYS : CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
            if (!out.ok()) fail(L"Écriture du cache impossible : " + win_error(GetLastError()));
            if (append) {
                LARGE_INTEGER z{};
                SetFilePointerEx(out.h, z, nullptr, FILE_END);
            }
            uint64_t n = offset;
            Meter m(L"Téléchargement", total, offset);
            std::vector<char> buf(1 << 20);
            for (;;) {
                check_cancel();
                DWORD got = 0;
                if (!WinHttpReadData(q.r, buf.data(), (DWORD)buf.size(), &got)) fail(L"Coupure réseau : " + win_error(GetLastError()), false);
                if (!got) break;
                DWORD wr = 0;
                if (!WriteFile(out.h, buf.data(), got, &wr, nullptr) || wr != got) fail(L"Écriture du cache impossible : " + win_error(GetLastError()));
                n += got;
                if (total && n > total) {
                    out.close();
                    DeleteFileW(part.c_str());
                    fail(L"Fichier plus gros qu'attendu : téléchargement rejeté");
                }
                m.tick(n);
            }
            m.tick(n, true);
            FlushFileBuffers(out.h);
            out.close();
            if (total && n != total) fail(F(L"Téléchargement incomplet : %ls / %ls", human(n).c_str(), human(total).c_str()), false);
            if (!MoveFileExW(part.c_str(), dest.c_str(), MOVEFILE_REPLACE_EXISTING)) fail(L"Renommage impossible : " + win_error(GetLastError()));
            DeleteFileW(meta.c_str());
            return;
        } catch (AppError& e) {
            if (e.fatal) throw;
            last = e;
            post_log(F(L"Tentative %d/8 : %ls", attempt, e.msg.c_str()));
            if (attempt < 8) sleep_cancellable(std::min(attempt * 2, 12));
        }
    }
    fail(L"Échec après 8 tentatives : " + last.msg);
}

static std::wstring acquire(const Firmware& fw, bool& from_cache) {
    std::wstring dir = g_cache + L"\\" + fw.version;
    make_dirs(dir);
    std::wstring dest = dir + L"\\PS5UPDATE.PUP";
    if (file_exists(dest) && (!fw.size || file_size(dest) == fw.size)) {
        post_log(L"PUP déjà présent dans le cache : il sera contrôlé pendant la copie");
        from_cache = true;
        return dest;
    }
    from_cache = false;
    bool mega_ok = !fw.mega.empty() && !megacmd().empty();
    if (!fw.direct.empty()) {
        try {
            download_http(fw, dest);
        } catch (AppError& e) {
            if (!mega_ok) throw;
            post_log(L"Miroir HTTPS indisponible (" + e.msg + L"). Essai via MEGA…");
            download_mega(fw, dest);
        }
    } else if (mega_ok) {
        download_mega(fw, dest);
    } else {
        fail(L"Aucune source automatique pour cette version. Télécharge le PUP puis glisse-le dans la fenêtre.");
    }
    check_header(dest);
    std::string md5;
    std::string sha = hash_file(dest, false, L"Vérification du téléchargement", &md5);
    if (sha != fw.sha256) {
        DeleteFileW(dest.c_str());
        fail(L"SHA-256 du téléchargement différent de la référence : fichier supprimé.\nAttendu : " + W(fw.sha256) + L"\nObtenu  : " + W(sha));
    }
    if (!fw.md5.empty() && md5 != fw.md5) {
        DeleteFileW(dest.c_str());
        fail(L"SHA-256 correct mais MD5 différent : références incohérentes, fichier supprimé");
    }
    post_log(L"Téléchargement vérifié (SHA-256 conforme)");
    return dest;
}

static void copy_and_verify(const std::wstring& src, const Drive& sel, const Firmware& fw, bool src_is_cache, bool delete_old) {
    Drive d = recheck_drive(sel);
    if (!d.fs_ok()) fail(L"La clé est en " + d.fs + L" : FAT32 ou exFAT requis. Utilise « Formater exFAT ».");
    uint64_t n = file_size(src);
    if (n < MIN_BYTES) fail(L"PUP trop petit : " + human(n));
    if (fw.size && n != fw.size) fail(F(L"Taille inattendue : %llu octets au lieu de %llu", (unsigned long long)n, (unsigned long long)fw.size));
    if (d.fs_ok() && wlower(d.fs) == L"fat32" && n >= 0xFFFFFFFFull) fail(L"Fichier > 4 Gio : exFAT obligatoire");
    check_header(src);
    std::wstring dir = d.root() + L"PS5\\UPDATE";
    std::wstring fin = dir + L"\\PS5UPDATE.PUP", staging = dir + L"\\PS5UPDATE.PUP.tmp";
    uint64_t old = file_exists(fin) ? file_size(fin) : 0;
    if (delete_old && old) {
        if (!DeleteFileW(fin.c_str())) fail(L"Suppression de l'ancien PUP impossible : " + win_error(GetLastError()));
        post_log(L"Ancien PS5UPDATE.PUP supprimé pour libérer de la place");
        d = recheck_drive(sel);
    }
    DeleteFileW(staging.c_str());
    if (d.free < n + HEADROOM) fail(L"Espace libre insuffisant sur la clé : " + human(d.free) + L" disponibles, il faut " + human(n + HEADROOM));
    CreateDirectoryW((d.root() + L"PS5").c_str(), nullptr);
    CreateDirectoryW(dir.c_str(), nullptr);
    post_log(L"Copie vers " + fin);
    struct Guard {
        std::wstring p;
        bool armed = true;
        ~Guard() { if (armed) DeleteFileW(p.c_str()); }
    } guard{staging};
    std::string src_sha;
    {
        Handle in(CreateFileW(src.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        if (!in.ok()) fail(L"Lecture du PUP impossible : " + win_error(GetLastError()));
        Handle out(CreateFileW(staging.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        if (!out.ok()) fail(L"Écriture sur la clé impossible : " + win_error(GetLastError()));
        Hasher sha(BCRYPT_SHA256_ALGORITHM);
        AlignedBuf buf(BLOCK);
        Meter m(L"Copie sur la clé", n);
        uint64_t copied = 0;
        for (;;) {
            check_cancel();
            DWORD got = 0;
            if (!ReadFile(in.h, buf.p, BLOCK, &got, nullptr)) fail(L"Lecture : " + win_error(GetLastError()));
            if (!got) break;
            sha.update(buf.p, got);
            DWORD wr = 0;
            if (!WriteFile(out.h, buf.p, got, &wr, nullptr) || wr != got) fail(L"Écriture sur la clé : " + win_error(GetLastError()));
            copied += got;
            m.tick(copied);
        }
        m.tick(copied, true);
        post_prog(L"Vidage du cache d'écriture…", 0, 0, L"Ne débranche pas la clé");
        if (!FlushFileBuffers(out.h)) fail(L"Vidage du cache impossible : " + win_error(GetLastError()));
        src_sha = sha.hex();
        if (copied != n) fail(L"Copie incomplète");
    }
    if (src_sha != fw.sha256) {
        if (src_is_cache) DeleteFileW(src.c_str());
        fail(std::wstring(L"SHA-256 du PUP source différent de la référence") + (src_is_cache ? L" : copie en cache corrompue supprimée, relance la préparation." : L".") +
             L"\nAttendu : " + W(fw.sha256) + L"\nObtenu  : " + W(src_sha));
    }
    post_log(L"Source conforme. Relecture directe depuis la clé (sans cache Windows)…");
    std::string back = hash_file(staging, true, L"Relecture de la clé USB");
    if (back != fw.sha256) fail(L"La relecture de la clé ne correspond pas : clé défectueuse ou contrefaite ? Essaie une autre clé.");
    if (!MoveFileExW(staging.c_str(), fin.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        fail(L"Renommage final impossible : " + win_error(GetLastError()));
    guard.armed = false;
    post_log(L"Copie relue et vérifiée : PS5\\UPDATE\\PS5UPDATE.PUP");
}

static void format_drive(const Drive& sel) {
    Drive d = recheck_drive(sel);
    wchar_t tmp[MAX_PATH]{}, sysdir[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp);
    GetSystemDirectoryW(sysdir, MAX_PATH);
    std::wstring log = std::wstring(tmp) + L"ps5usbprep_format.log";
    DeleteFileW(log.c_str());
    std::wstring cmd = std::wstring(sysdir) + L"\\cmd.exe";
    std::wstring params = F(L"/d /c \"echo.| \"%ls\\format.com\" %lc: /FS:exFAT /Q /V:PS5 /X /Y > \"%ls\" 2>&1\"", sysdir, d.letter, log.c_str());
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof sei;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.hwnd = g_hwnd;
    sei.lpVerb = L"runas";
    sei.lpFile = cmd.c_str();
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;
    post_prog(L"Formatage exFAT…", 0, 0, L"Accepte la demande d'administrateur Windows");
    if (!ShellExecuteExW(&sei)) {
        DWORD e = GetLastError();
        if (e == ERROR_CANCELLED) fail(L"Droits administrateur refusés : formatage annulé");
        fail(L"Lancement du formatage impossible : " + win_error(e));
    }
    if (!sei.hProcess) fail(L"Processus de formatage introuvable");
    Handle proc(sei.hProcess);
    post_prog(L"Formatage exFAT…", 0, 0, L"Ne débranche pas la clé");
    post_log(F(L"Formatage de %lc: en exFAT (nom PS5)…", d.letter));
    WaitForSingleObject(proc.h, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(proc.h, &code);
    Handle lh(CreateFileW(log.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    std::wstring text;
    if (lh.ok()) {
        std::string s(65536, 0);
        DWORD got = 0;
        ReadFile(lh.h, s.data(), (DWORD)s.size(), &got, nullptr);
        s.resize(got);
        text = trim(WCP(s, CP_OEMCP));
    }
    lh.close();
    DeleteFileW(log.c_str());
    if (code != 0) {
        if (text.size() > 600) text = text.substr(text.size() - 600);
        fail(F(L"format.com a échoué (code %lu).\n", code) + text);
    }
    Sleep(1000);
    Drive after = recheck_drive(sel);
    post_log(L"Formatage terminé : " + after.fs + L", " + human(after.size));
}

static void eject_drive(const Drive& sel) {
    Drive d = recheck_drive(sel);
    HDEVINFO set = SetupDiGetClassDevsW(&kDiskGuid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (set == INVALID_HANDLE_VALUE) fail(L"SetupAPI indisponible");
    DEVINST inst = 0;
    for (DWORD i = 0;; i++) {
        SP_DEVICE_INTERFACE_DATA ifd{};
        ifd.cbSize = sizeof ifd;
        if (!SetupDiEnumDeviceInterfaces(set, nullptr, &kDiskGuid, i, &ifd)) break;
        DWORD need = 0;
        SetupDiGetDeviceInterfaceDetailW(set, &ifd, nullptr, 0, &need, nullptr);
        if (!need) continue;
        std::vector<BYTE> b(need);
        auto* det = (SP_DEVICE_INTERFACE_DETAIL_DATA_W*)b.data();
        det->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        SP_DEVINFO_DATA dd{};
        dd.cbSize = sizeof dd;
        if (!SetupDiGetDeviceInterfaceDetailW(set, &ifd, det, need, nullptr, &dd)) continue;
        HANDLE h = CreateFileW(det->DevicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        STORAGE_DEVICE_NUMBER n{};
        DWORD got = 0;
        bool ok = DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &n, sizeof n, &got, nullptr);
        CloseHandle(h);
        if (ok && n.DeviceNumber == d.disk && n.DeviceType == FILE_DEVICE_DISK) {
            inst = dd.DevInst;
            break;
        }
    }
    SetupDiDestroyDeviceInfoList(set);
    if (!inst) fail(L"Périphérique de la clé introuvable");
    DEVINST parent = 0;
    CM_Get_Parent(&parent, inst, 0);
    std::wstring veto_name;
    for (int a = 0; a < 5; a++) {
        for (DEVINST target : {inst, parent}) {
            if (!target) continue;
            PNP_VETO_TYPE veto = PNP_VetoTypeUnknown;
            wchar_t name[MAX_PATH]{};
            if (CM_Request_Device_EjectW(target, &veto, name, MAX_PATH, 0) == CR_SUCCESS && veto == PNP_VetoTypeUnknown) {
                post_log(F(L"Clé %lc: éjectée", d.letter));
                return;
            }
            if (name[0]) veto_name = name;
        }
        sleep_cancellable(1);
    }
    fail(L"Windows refuse l'éjection : un programme utilise encore la clé." + (veto_name.empty() ? L"" : L"\n" + veto_name));
}

struct DoneInfo {
    int kind = 0;
    std::wstring msg;
    int job = 0;
};
enum { JOB_PREPARE = 1, JOB_FORMAT, JOB_EJECT, JOB_IDENT };

struct IdentInfo {
    std::wstring path;
    std::string sha, md5;
    uint64_t size = 0;
};


namespace Gdiplus {
using std::max;
using std::min;
}
#include <gdiplus.h>
#include <dwmapi.h>
#include <uxtheme.h>

namespace C {
const COLORREF bg = RGB(13, 15, 20);
const COLORREF card = RGB(22, 25, 32);
const COLORREF border = RGB(36, 40, 50);
const COLORREF field = RGB(16, 18, 24);
const COLORREF fieldBorder = RGB(46, 51, 63);
const COLORREF hover = RGB(32, 36, 47);
const COLORREF press = RGB(27, 31, 40);
const COLORREF text = RGB(234, 236, 240);
const COLORREF dim = RGB(150, 157, 170);
const COLORREF faint = RGB(98, 105, 118);
const COLORREF accent = RGB(0, 112, 209);
const COLORREF accentHi = RGB(30, 136, 235);
const COLORREF accentLo = RGB(0, 90, 172);
const COLORREF sel = RGB(26, 44, 74);
const COLORREF ok = RGB(52, 199, 120);
const COLORREF okBg = RGB(20, 52, 38);
const COLORREF bad = RGB(240, 82, 87);
const COLORREF badBg = RGB(66, 25, 29);
const COLORREF warn = RGB(245, 170, 50);
}

enum BtnKind { BK_PRIMARY, BK_GHOST, BK_DANGER, BK_ICON, BK_DROP };
struct BtnInfo {
    int kind = BK_GHOST;
    wchar_t icon = 0;
    bool hot = false;
};

struct Ui {
    HWND drives, refresh, driveinfo, version, archives, site, cache, source, sha, drop, progress, status, detail;
    HWND start, cancel, format, eject, log, tip;
    HFONT font = nullptr, semi = nullptr, title = nullptr, small = nullptr, mono = nullptr, icon = nullptr, iconBig = nullptr;
    HBRUSH bgBrush = nullptr, cardBrush = nullptr, fieldBrush = nullptr;
    HICON appIcon = nullptr;
    std::wstring uiFont = L"Segoe UI", iconFont = L"Segoe MDL2 Assets", monoFont = L"Consolas";
    RECT cards[4]{}, logField{};
    UINT dpi = 96;
    ITaskbarList3* tb = nullptr;
    UINT tbmsg = 0;
    COLORREF status_color = C::text;
    COLORREF bar_color = C::accent;
    int bar_pos = 0;
    bool marquee = false;
    int phase = 0;
    bool closing = false;
    int close_ticks = 0;
    bool pending_scan = false;
    bool has_mega = false;
} ui;

enum { TIMER_ANIM = 3 };

static std::map<HWND, BtnInfo> g_btn;
static Catalog g_catalog;
static std::vector<std::wstring> g_versions;
static std::vector<Drive> g_drives;
static std::wstring g_local_path, g_local_version;
static std::wstring g_selected_version = L"13.60.00";
static std::wstring g_selected_drive_id;
static std::wstring g_drop_main, g_drop_sub;
static bool g_drop_ok = false;

static const wchar_t* DROP_MAIN = L"Glisse un fichier .PUP ici";
static const wchar_t* DROP_SUB = L"ou clique pour parcourir · version identifiée par SHA-256";

static int S(int v) { return MulDiv(v, (int)ui.dpi, 96); }
static Gdiplus::Color GC(COLORREF c, BYTE a = 255) { return Gdiplus::Color(a, GetRValue(c), GetGValue(c), GetBValue(c)); }

static void round_path(Gdiplus::GraphicsPath& p, float x, float y, float w, float h, float r) {
    float d = std::min(r * 2, std::min(w, h));
    p.AddArc(x, y, d, d, 180, 90);
    p.AddArc(x + w - d, y, d, d, 270, 90);
    p.AddArc(x + w - d, y + h - d, d, d, 0, 90);
    p.AddArc(x, y + h - d, d, d, 90, 90);
    p.CloseFigure();
}

static void rrect(HDC dc, const RECT& r, int rad, COLORREF fill, COLORREF stroke, bool dashed = false) {
    Gdiplus::Graphics g(dc);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);
    float x = (float)r.left, y = (float)r.top, w = (float)(r.right - r.left), h = (float)(r.bottom - r.top);
    if (fill != CLR_NONE) {
        Gdiplus::GraphicsPath p;
        round_path(p, x, y, w, h, (float)rad);
        Gdiplus::SolidBrush b(GC(fill));
        g.FillPath(&b, &p);
    }
    if (stroke != CLR_NONE) {
        Gdiplus::GraphicsPath p;
        round_path(p, x + 0.5f, y + 0.5f, w - 1, h - 1, (float)rad);
        Gdiplus::Pen pen(GC(stroke), 1.0f);
        if (dashed) {
            Gdiplus::REAL pat[] = {4.0f, 3.0f};
            pen.SetDashPattern(pat, 2);
        }
        g.DrawPath(&pen, &p);
    }
}

static void circle(HDC dc, int cx, int cy, int r, COLORREF fill) {
    Gdiplus::Graphics g(dc);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);
    Gdiplus::SolidBrush b(GC(fill));
    g.FillEllipse(&b, (float)(cx - r), (float)(cy - r), (float)(2 * r), (float)(2 * r));
}

static void draw_text(HDC dc, const std::wstring& s, RECT r, HFONT f, COLORREF c, UINT fmt) {
    HGDIOBJ o = SelectObject(dc, f);
    SetTextColor(dc, c);
    SetBkMode(dc, TRANSPARENT);
    DrawTextW(dc, s.c_str(), -1, &r, fmt | DT_NOPREFIX);
    SelectObject(dc, o);
}

static int text_width(HDC dc, const std::wstring& s, HFONT f) {
    HGDIOBJ o = SelectObject(dc, f);
    SIZE sz{};
    GetTextExtentPoint32W(dc, s.c_str(), (int)s.size(), &sz);
    SelectObject(dc, o);
    return sz.cx;
}

struct MemDC {
    HDC dst, dc;
    HBITMAP bmp;
    HGDIOBJ old;
    int w, h;
    MemDC(HDC d, int w_, int h_) : dst(d), w(w_), h(h_) {
        dc = CreateCompatibleDC(d);
        bmp = CreateCompatibleBitmap(d, std::max(1, w), std::max(1, h));
        old = SelectObject(dc, bmp);
    }
    ~MemDC() {
        BitBlt(dst, 0, 0, w, h, dc, 0, 0, SRCCOPY);
        SelectObject(dc, old);
        DeleteObject(bmp);
        DeleteDC(dc);
    }
};

static void fill(HDC dc, const RECT& r, COLORREF c) {
    HBRUSH b = CreateSolidBrush(c);
    FillRect(dc, &r, b);
    DeleteObject(b);
}

static void set_text(HWND h, const std::wstring& s) { SetWindowTextW(h, s.c_str()); }

static void log_line(const std::wstring& s) {
    SYSTEMTIME t;
    GetLocalTime(&t);
    std::wstring body = s;
    size_t p = 0;
    while ((p = body.find(L'\n', p)) != std::wstring::npos) {
        if (p == 0 || body[p - 1] != L'\r') { body.insert(p, L"\r"); p += 2; }
        else p++;
    }
    std::wstring line = F(L"%02d:%02d:%02d   ", t.wHour, t.wMinute, t.wSecond) + body + L"\r\n";
    int len = GetWindowTextLengthW(ui.log);
    SendMessageW(ui.log, EM_SETSEL, len, len);
    SendMessageW(ui.log, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
    SendMessageW(ui.log, EM_SCROLLCARET, 0, 0);
}

static void set_status(const std::wstring& s, COLORREF c = C::text) {
    ui.status_color = c;
    set_text(ui.status, s);
    InvalidateRect(ui.status, nullptr, TRUE);
}

static void redraw_bar() { InvalidateRect(ui.progress, nullptr, FALSE); }

static void set_marquee(bool on) {
    if (on == ui.marquee) return;
    ui.marquee = on;
    if (on) SetTimer(g_hwnd, TIMER_ANIM, 16, nullptr);
    else KillTimer(g_hwnd, TIMER_ANIM);
    redraw_bar();
}

static void set_bar(int pos, COLORREF c = C::accent) {
    ui.bar_pos = pos;
    ui.bar_color = c;
    redraw_bar();
}

static void set_progress(uint64_t cur, uint64_t total) {
    if (!total) {
        set_marquee(true);
        if (ui.tb) ui.tb->SetProgressState(g_hwnd, TBPF_INDETERMINATE);
        return;
    }
    set_marquee(false);
    int pos = (int)std::min<uint64_t>(1000, cur * 1000 / total);
    set_bar(pos);
    if (ui.tb) {
        ui.tb->SetProgressState(g_hwnd, TBPF_NORMAL);
        ui.tb->SetProgressValue(g_hwnd, pos, 1000);
    }
}

static const Drive* selected_drive() {
    int i = (int)SendMessageW(ui.drives, CB_GETCURSEL, 0, 0);
    return (i >= 0 && i < (int)g_drives.size()) ? &g_drives[i] : nullptr;
}

static const Firmware* selected_fw() {
    int i = (int)SendMessageW(ui.version, CB_GETCURSEL, 0, 0);
    if (i < 0 || i >= (int)g_versions.size()) return nullptr;
    auto it = g_catalog.find(g_versions[i]);
    return it == g_catalog.end() ? nullptr : &it->second;
}

static bool mega_auto(const Firmware& f) { return !f.mega.empty() && ui.has_mega; }

static std::wstring cache_path(const Firmware& f) { return g_cache + L"\\" + f.version + L"\\PS5UPDATE.PUP"; }

static bool in_cache(const Firmware& f) {
    std::wstring p = cache_path(f);
    return file_exists(p) && (!f.size || file_size(p) == f.size);
}

static std::wstring source_tag(const Firmware& f) {
    if (!is_hex(f.sha256, 64)) return L"sans SHA-256";
    if (in_cache(f)) return L"en cache";
    if (!f.direct.empty()) return L"HTTPS";
    if (!f.mega.empty()) return mega_auto(f) ? L"MEGAcmd" : L"MEGA manuel";
    return L"fichier local";
}

static bool step1_ready() {
    const Drive* d = selected_drive();
    return d && d->fs_ok();
}

static bool step2_ready() {
    const Firmware* f = selected_fw();
    if (!f || !is_hex(f->sha256, 64)) return false;
    return (!g_local_path.empty() && g_local_version == f->version) || !f->direct.empty() || mega_auto(*f) || in_cache(*f);
}

static void refresh_steps() {
    for (int i = 0; i < 2; i++) InvalidateRect(g_hwnd, &ui.cards[i], FALSE);
}

static void update_drive_info() {
    InvalidateRect(ui.driveinfo, nullptr, FALSE);
    refresh_steps();
}

static void reset_drop() {
    g_drop_main = DROP_MAIN;
    g_drop_sub = DROP_SUB;
    g_drop_ok = false;
    g_btn[ui.drop].icon = 0xE896;
    InvalidateRect(ui.drop, nullptr, FALSE);
}

static void update_fw_info() {
    const Firmware* f = selected_fw();
    if (!f) return;
    std::wstring src;
    if (!g_local_path.empty() && g_local_version == f->version) src = L"Source : fichier local identifié";
    else if (in_cache(*f)) src = L"Source : déjà téléchargé (cache local)";
    else if (!f->direct.empty()) src = L"Source : téléchargement HTTPS direct, reprise automatique";
    else if (!f->mega.empty()) src = mega_auto(*f) ? L"Source : MEGA automatique via MEGAcmd" : L"Source : MEGA — télécharge-le puis glisse le .PUP ci-dessous";
    else src = L"Source : aucun lien — glisse le .PUP ci-dessous";
    if (f->size) src += L"   ·   " + human(f->size);
    set_text(ui.source, src);
    set_text(ui.sha, L"SHA-256  " + (is_hex(f->sha256, 64) ? W(f->sha256) : std::wstring(L"inconnu — copie bloquée")));
    refresh_steps();
}

static void fill_versions() {
    g_versions.clear();
    for (auto& kv : g_catalog) g_versions.push_back(kv.first);
    std::sort(g_versions.begin(), g_versions.end(), [](const std::wstring& a, const std::wstring& b) { return version_key(a) > version_key(b); });
    SendMessageW(ui.version, CB_RESETCONTENT, 0, 0);
    int sel = -1, fallback = -1;
    for (size_t i = 0; i < g_versions.size(); i++) {
        auto& f = g_catalog[g_versions[i]];
        std::wstring item = L"Firmware " + f.version + L"\t" + source_tag(f);
        SendMessageW(ui.version, CB_ADDSTRING, 0, (LPARAM)item.c_str());
        if (f.version == g_selected_version) sel = (int)i;
        if (f.version == L"13.60.00") fallback = (int)i;
    }
    if (sel < 0) sel = fallback >= 0 ? fallback : (g_versions.empty() ? -1 : 0);
    SendMessageW(ui.version, CB_SETCURSEL, sel, 0);
    if (sel >= 0) g_selected_version = g_versions[sel];
    update_fw_info();
}

static void fill_drives() {
    SendMessageW(ui.drives, CB_RESETCONTENT, 0, 0);
    int sel = g_drives.empty() ? -1 : 0;
    for (size_t i = 0; i < g_drives.size(); i++) {
        auto& d = g_drives[i];
        std::wstring name = d.model.empty() ? L"Clé USB" : d.model;
        if (!d.label.empty()) name += L"  (" + d.label + L")";
        std::wstring item = F(L"%lc:   ", d.letter) + name + L"\t" + human(d.size);
        SendMessageW(ui.drives, CB_ADDSTRING, 0, (LPARAM)item.c_str());
        if (d.id == g_selected_drive_id) sel = (int)i;
    }
    if (g_drives.empty()) {
        SendMessageW(ui.drives, CB_ADDSTRING, 0, (LPARAM)L"Aucune clé USB détectée\t");
        SendMessageW(ui.drives, CB_SETCURSEL, 0, 0);
    } else SendMessageW(ui.drives, CB_SETCURSEL, sel, 0);
    if (sel >= 0 && !g_drives.empty()) g_selected_drive_id = g_drives[sel].id;
    update_drive_info();
}

static void apply_busy() {
    bool b = g_busy;
    bool has = selected_drive() != nullptr;
    for (HWND h : {ui.drives, ui.version, ui.drop, ui.cache}) EnableWindow(h, !b);
    EnableWindow(ui.refresh, !b && !g_scanning);
    EnableWindow(ui.archives, !b && !g_catalog_loading);
    EnableWindow(ui.start, !b && has);
    EnableWindow(ui.format, !b && has);
    EnableWindow(ui.eject, !b && has);
    EnableWindow(ui.cancel, b);
    DragAcceptFiles(g_hwnd, !b);
    set_text(ui.start, b ? L"En cours…" : L"Préparer la clé");
}

static void scan_drives() {
    if (g_scanning) return;
    if (g_busy) { ui.pending_scan = true; return; }
    g_scanning = true;
    apply_busy();
    std::thread([] {
        auto* v = new std::vector<Drive>();
        try { *v = list_usb(); } catch (...) {}
        PostMessageW(g_hwnd, WM_DRIVES, 0, (LPARAM)v);
    }).detach();
}

static void load_catalog() {
    if (g_catalog_loading) return;
    g_catalog_loading = true;
    apply_busy();
    post_log(L"Lecture des archives communautaires…");
    std::thread([] {
        auto* c = new Catalog(scan_catalog());
        PostMessageW(g_hwnd, WM_CATALOG, 0, (LPARAM)c);
    }).detach();
}

static void run_job(int job, std::function<std::wstring()> fn) {
    g_cancel = false;
    g_busy = true;
    apply_busy();
    set_status(L"Démarrage…");
    set_bar(0);
    set_text(ui.detail, L"");
    std::thread([job, fn] {
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        auto* d = new DoneInfo;
        d->job = job;
        try {
            d->msg = fn();
            d->kind = 0;
        } catch (Cancelled& c) {
            d->kind = 1;
            d->msg = c.msg;
        } catch (AppError& e) {
            d->kind = 2;
            d->msg = e.msg;
        } catch (std::exception& e) {
            d->kind = 2;
            d->msg = W(e.what());
        }
        CoUninitialize();
        PostMessageW(g_hwnd, WM_DONE, 0, (LPARAM)d);
    }).detach();
}

static int ask(const std::wstring& text, const wchar_t* title, UINT flags) { return MessageBoxW(g_hwnd, text.c_str(), title, flags); }

static void identify_local(const std::wstring& path) {
    if (g_busy) return;
    log_line(L"Identification de " + path);
    run_job(JOB_IDENT, [path]() -> std::wstring {
        check_header(path);
        uint64_t n = file_size(path);
        if (n < MIN_BYTES) fail(L"Fichier trop petit pour un PUP système : " + human(n));
        auto* info = new IdentInfo;
        info->path = path;
        info->size = n;
        try {
            info->sha = hash_file(path, false, L"Identification du PUP", &info->md5);
        } catch (...) {
            delete info;
            throw;
        }
        PostMessageW(g_hwnd, WM_IDENT, 0, (LPARAM)info);
        return L"";
    });
}

static void on_ident(IdentInfo* info) {
    std::unique_ptr<IdentInfo> g(info);
    for (auto& kv : g_catalog) {
        if (kv.second.sha256 == info->sha) {
            if (!kv.second.md5.empty() && kv.second.md5 != info->md5) {
                ask(L"SHA-256 reconnu mais MD5 incohérent : fichier refusé.", APP_NAME, MB_ICONERROR);
                return;
            }
            g_local_path = info->path;
            g_local_version = kv.first;
            g_selected_version = kv.first;
            fill_versions();
            g_drop_main = info->path.substr(info->path.find_last_of(L"\\/") + 1);
            g_drop_sub = L"Firmware " + kv.first + L" identifié · SHA-256 conforme · " + human(info->size);
            g_drop_ok = true;
            g_btn[ui.drop].icon = 0xE73E;
            InvalidateRect(ui.drop, nullptr, FALSE);
            log_line(L"PUP local identifié : firmware " + kv.first);
            return;
        }
    }
    g_local_path.clear();
    g_local_version.clear();
    reset_drop();
    log_line(L"PUP inconnu, SHA-256 : " + W(info->sha));
    ask(L"Ce PUP ne correspond à aucune référence SHA-256 connue.\n\nC'est peut-être un PUP Recovery, un fichier modifié ou une version absente du catalogue (actualise les archives, ou ajoute son hash dans sha256_references.json à côté de l'exe).\n\nSHA-256 : " +
            W(info->sha),
        APP_NAME, MB_ICONWARNING);
}

static void choose_local() {
    wchar_t file[MAX_PATH * 4]{};
    OPENFILENAMEW of{};
    of.lStructSize = sizeof of;
    of.hwndOwner = g_hwnd;
    of.lpstrFilter = L"Firmware PS5 (*.PUP)\0*.pup\0Tous les fichiers\0*.*\0";
    of.lpstrFile = file;
    of.nMaxFile = MAX_PATH * 4;
    of.lpstrTitle = L"Choisir un firmware PS5 (Update)";
    of.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileNameW(&of)) identify_local(file);
}

static void start_eject();

static void start_prepare() {
    const Drive* dp = selected_drive();
    const Firmware* fp = selected_fw();
    if (!dp) { ask(L"Sélectionne une clé USB.", APP_NAME, MB_ICONWARNING); return; }
    if (!fp || !is_hex(fp->sha256, 64)) { ask(L"Cette version n'a pas de SHA-256 de référence : copie bloquée.", APP_NAME, MB_ICONERROR); return; }
    Drive d = *dp;
    Firmware fw = *fp;
    if (!d.fs_ok()) {
        if (ask(L"La clé " + std::wstring(1, d.letter) + L": est en " + d.fs + L", que la PS5 ne lit pas.\n\nLa formater en exFAT maintenant ?\nTOUTES ses données seront effacées.", APP_NAME,
                MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) == IDYES)
            run_job(JOB_FORMAT, [d]() { format_drive(d); return std::wstring(L"Clé formatée en exFAT. Relance « Préparer la clé »."); });
        return;
    }
    bool use_local = !g_local_path.empty() && g_local_version == fw.version;
    if (use_local && !file_exists(g_local_path)) {
        ask(L"Le fichier local n'existe plus.", APP_NAME, MB_ICONERROR);
        g_local_path.clear();
        reset_drop();
        return;
    }
    std::wstring cached = cache_path(fw);
    bool have_cache = in_cache(fw);
    if (!use_local && !have_cache && fw.direct.empty() && !mega_auto(fw)) {
        if (!fw.mega.empty()) {
            if (ask(L"Cette version n'est disponible que sur MEGA.\n\nOuvrir le lien dans le navigateur ? Une fois téléchargé, glisse le .PUP dans la fenêtre.\n(Ou installe MEGAcmd pour le téléchargement automatique.)", APP_NAME,
                    MB_ICONINFORMATION | MB_YESNO) == IDYES)
                ShellExecuteW(g_hwnd, L"open", fw.mega.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        } else ask(L"Aucun lien pour cette version. Télécharge le PUP puis glisse-le dans la fenêtre.", APP_NAME, MB_ICONINFORMATION);
        return;
    }
    uint64_t need = use_local ? file_size(g_local_path) : (have_cache ? file_size(cached) : fw.size);
    std::wstring fin = d.root() + L"PS5\\UPDATE\\PS5UPDATE.PUP";
    uint64_t old = file_exists(fin) ? file_size(fin) : 0;
    bool delete_old = false;
    if (old && ask(L"Un PS5UPDATE.PUP existe déjà sur " + d.root() + L".\nLe remplacer (après vérification du nouveau) ?", APP_NAME, MB_ICONQUESTION | MB_YESNO) != IDYES) return;
    if (need && d.free < need + HEADROOM) {
        if (old && d.free + old >= need + HEADROOM) {
            if (ask(L"Pas assez de place pour garder l'ancien PUP pendant la copie.\nSupprimer l'ancien d'abord ?", APP_NAME, MB_ICONQUESTION | MB_YESNO) != IDYES) return;
            delete_old = true;
        } else {
            ask(L"Espace insuffisant sur la clé : " + human(d.free) + L" libres, il faut " + human(need + HEADROOM) + L".", APP_NAME, MB_ICONERROR);
            return;
        }
    }
    std::wstring how = use_local ? L"fichier local" : have_cache ? L"cache local" : !fw.direct.empty() ? L"téléchargement HTTPS" : L"MEGAcmd";
    if (ask(L"Firmware : " + fw.version + L"  (" + how + L")\nClé : " + d.root() + L"  " + d.model + L"  ·  " + d.fs + L"  ·  " + human(d.size) +
                L"\n\nSeul PS5\\UPDATE\\PS5UPDATE.PUP sera créé ou remplacé. La clé ne sera pas formatée.\nUne PS5 peut refuser une version plus ancienne que la sienne.\n\nContinuer ?",
            L"Préparer la clé", MB_ICONQUESTION | MB_YESNO) != IDYES)
        return;
    std::wstring local = use_local ? g_local_path : L"";
    run_job(JOB_PREPARE, [d, fw, local, delete_old]() {
        make_dirs(g_cache);
        bool from_cache = false;
        std::wstring src = local.empty() ? acquire(fw, from_cache) : local;
        copy_and_verify(src, d, fw, from_cache, delete_old);
        return d.root() + L"PS5\\UPDATE\\PS5UPDATE.PUP";
    });
}

static void start_format() {
    const Drive* dp = selected_drive();
    if (!dp) return;
    Drive d = *dp;
    if (ask(F(L"Formater %lc:  %ls  (%ls) en exFAT ?\n\nTOUTES LES DONNÉES DE CETTE CLÉ SERONT EFFACÉES.\nWindows va demander les droits administrateur.", d.letter, d.model.c_str(), human(d.size).c_str()),
            L"Formater la clé", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES)
        return;
    run_job(JOB_FORMAT, [d]() { format_drive(d); return std::wstring(L"Clé formatée en exFAT (nom PS5)"); });
}

static void start_eject() {
    const Drive* dp = selected_drive();
    if (!dp) return;
    Drive d = *dp;
    run_job(JOB_EJECT, [d]() { eject_drive(d); return F(L"%lc: peut être retirée en toute sécurité", d.letter); });
}

static bool font_exists(const wchar_t* name) {
    LOGFONTW lf{};
    lf.lfCharSet = DEFAULT_CHARSET;
    wcsncpy(lf.lfFaceName, name, LF_FACESIZE - 1);
    HDC dc = GetDC(nullptr);
    bool found = false;
    EnumFontFamiliesExW(dc, &lf, [](const LOGFONTW*, const TEXTMETRICW*, DWORD, LPARAM p) -> int { *(bool*)p = true; return 0; }, (LPARAM)&found, 0);
    ReleaseDC(nullptr, dc);
    return found;
}

static HFONT mkfont(const std::wstring& face, double pt, int weight) {
    return CreateFontW(-(int)(pt * ui.dpi / 72.0 + 0.5), 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, face.c_str());
}

static void make_fonts() {
    for (HFONT f : {ui.font, ui.semi, ui.title, ui.small, ui.mono, ui.icon, ui.iconBig})
        if (f) DeleteObject(f);
    ui.font = mkfont(ui.uiFont, 9, FW_NORMAL);
    ui.semi = mkfont(ui.uiFont, 9, FW_SEMIBOLD);
    ui.title = mkfont(ui.uiFont, 14, FW_SEMIBOLD);
    ui.small = mkfont(ui.uiFont, 8, FW_NORMAL);
    ui.mono = mkfont(ui.monoFont, 8, FW_NORMAL);
    ui.icon = mkfont(ui.iconFont, 9, FW_NORMAL);
    ui.iconBig = mkfont(ui.iconFont, 15, FW_NORMAL);
    EnumChildWindows(g_hwnd, [](HWND c, LPARAM) -> BOOL { SendMessageW(c, WM_SETFONT, (WPARAM)ui.font, TRUE); return TRUE; }, 0);
    SendMessageW(ui.sha, WM_SETFONT, (WPARAM)ui.mono, TRUE);
    SendMessageW(ui.log, WM_SETFONT, (WPARAM)ui.mono, TRUE);
    SendMessageW(ui.status, WM_SETFONT, (WPARAM)ui.semi, TRUE);
    SendMessageW(ui.detail, WM_SETFONT, (WPARAM)ui.small, TRUE);
    SendMessageW(ui.source, WM_SETFONT, (WPARAM)ui.small, TRUE);
    for (HWND cb : {ui.drives, ui.version}) {
        SendMessageW(cb, CB_SETITEMHEIGHT, (WPARAM)-1, S(26));
        SendMessageW(cb, CB_SETITEMHEIGHT, 0, S(28));
    }
    if (ui.appIcon) DestroyIcon(ui.appIcon);
    ui.appIcon = (HICON)LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1), IMAGE_ICON, S(30), S(30), 0);
}

static void layout() {
    RECT rc;
    GetClientRect(g_hwnd, &rc);
    int m = S(16), cw = rc.right - 2 * m, pad = S(16), y = S(66);
    auto place = [](HWND h, int x, int y2, int w, int hh) { MoveWindow(h, x, y2, w, hh, FALSE); };
    int bh = S(28);

    RECT& c0 = ui.cards[0];
    c0 = {m, y, m + cw, y + S(118)};
    int x = c0.left + pad, iw = cw - 2 * pad;
    place(ui.eject, c0.right - pad - S(86), c0.top + S(12), S(86), bh);
    place(ui.format, c0.right - pad - S(86) - S(6) - S(100), c0.top + S(12), S(100), bh);
    place(ui.drives, x, c0.top + S(50), iw - S(40), S(300));
    place(ui.refresh, c0.right - pad - S(34), c0.top + S(50), S(34), S(30));
    place(ui.driveinfo, x, c0.top + S(88), iw, S(20));
    y = c0.bottom + S(12);

    RECT& c1 = ui.cards[1];
    c1 = {m, y, m + cw, y + S(196)};
    place(ui.cache, c1.right - pad - S(34), c1.top + S(12), S(34), bh);
    place(ui.site, c1.right - pad - S(34) * 2 - S(6), c1.top + S(12), S(34), bh);
    place(ui.archives, c1.right - pad - S(34) * 3 - S(12), c1.top + S(12), S(34), bh);
    place(ui.version, x, c1.top + S(50), iw, S(300));
    place(ui.source, x, c1.top + S(88), iw, S(18));
    place(ui.sha, x, c1.top + S(107), iw, S(16));
    place(ui.drop, x, c1.top + S(132), iw, S(50));
    y = c1.bottom + S(12);

    RECT& c2 = ui.cards[2];
    c2 = {m, y, m + cw, y + S(140)};
    place(ui.status, x, c2.top + S(48), iw * 55 / 100, S(20));
    place(ui.detail, x + iw * 55 / 100, c2.top + S(50), iw - iw * 55 / 100, S(18));
    place(ui.progress, x, c2.top + S(74), iw, S(8));
    place(ui.start, x, c2.top + S(94), iw - S(110), S(34));
    place(ui.cancel, c2.right - pad - S(102), c2.top + S(94), S(102), S(34));
    y = c2.bottom + S(12);

    RECT& c3 = ui.cards[3];
    c3 = {m, y, m + cw, std::max(y + S(110), (int)rc.bottom - m)};
    ui.logField = {x - S(4), c3.top + S(44), c3.right - pad + S(4), c3.bottom - S(12)};
    place(ui.log, ui.logField.left + S(8), ui.logField.top + S(6), ui.logField.right - ui.logField.left - S(10), ui.logField.bottom - ui.logField.top - S(10));
    InvalidateRect(g_hwnd, nullptr, TRUE);
    RedrawWindow(g_hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_ERASE);
}

static void paint(HDC hdc) {
    RECT rc;
    GetClientRect(g_hwnd, &rc);
    MemDC mem(hdc, rc.right, rc.bottom);
    HDC dc = mem.dc;
    fill(dc, rc, C::bg);
    int m = S(16);
    if (ui.appIcon) DrawIconEx(dc, m, S(18), ui.appIcon, S(30), S(30), 0, nullptr, DI_NORMAL);
    draw_text(dc, L"PSD", {m + S(42), S(14), rc.right, S(36)}, ui.title, C::text, DT_LEFT | DT_SINGLELINE);
    draw_text(dc, L"PS5 USB Prep · clé de mise à jour officielle, vérifiée bout à bout", {m + S(42), S(36), rc.right, S(54)}, ui.small, C::dim, DT_LEFT | DT_SINGLELINE);
    std::wstring ver = std::wstring(L"v") + APP_VER;
    int vw = text_width(dc, ver, ui.small) + S(16);
    RECT pill{rc.right - m - vw, S(22), rc.right - m, S(42)};
    rrect(dc, pill, S(10), C::card, C::border);
    draw_text(dc, ver, pill, ui.small, C::dim, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    const wchar_t* titles[] = {L"Clé USB", L"Firmware", L"Préparation", L"Journal"};
    bool ready[] = {step1_ready(), step2_ready(), false, false};
    for (int i = 0; i < 4; i++) {
        RECT c = ui.cards[i];
        rrect(dc, c, S(12), C::card, C::border);
        int tx = c.left + S(16), cy = c.top + S(26);
        if (i < 3) {
            int r = S(11);
            circle(dc, tx + r, cy, r, ready[i] ? C::okBg : RGB(30, 40, 58));
            RECT cr{tx, cy - r, tx + 2 * r, cy + r};
            if (ready[i]) draw_text(dc, L"\xE73E", cr, ui.icon, C::ok, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            else draw_text(dc, std::to_wstring(i + 1), cr, ui.semi, C::accentHi, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            tx += 2 * r + S(10);
        } else {
            RECT ir{tx, cy - S(10), tx + S(20), cy + S(10)};
            draw_text(dc, L"\xE81C", ir, ui.icon, C::faint, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            tx += S(28);
        }
        draw_text(dc, titles[i], {tx, cy - S(12), c.right - S(140), cy + S(12)}, ui.semi, C::text, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }
    rrect(dc, ui.logField, S(8), C::field, C::fieldBorder);
}

static void draw_button(DRAWITEMSTRUCT* di) {
    auto& b = g_btn[di->hwndItem];
    RECT r = di->rcItem;
    int w = r.right - r.left, h = r.bottom - r.top;
    MemDC mem(di->hDC, w, h);
    HDC dc = mem.dc;
    RECT full{0, 0, w, h};
    fill(dc, full, C::card);
    bool dis = di->itemState & ODS_DISABLED, down = di->itemState & ODS_SELECTED;
    bool focus = (di->itemState & ODS_FOCUS) && !(di->itemState & ODS_NOFOCUSRECT);
    bool hot = b.hot && !dis;
    COLORREF bg, br, fg;
    switch (b.kind) {
    case BK_PRIMARY:
        bg = dis ? RGB(34, 39, 50) : down ? C::accentLo : hot ? C::accentHi : C::accent;
        br = CLR_NONE;
        fg = dis ? C::faint : RGB(255, 255, 255);
        break;
    case BK_DROP:
        bg = dis ? C::field : hot ? RGB(18, 26, 40) : C::field;
        br = g_drop_ok ? C::ok : hot ? C::accentHi : C::fieldBorder;
        fg = C::text;
        break;
    default:
        bg = dis ? C::card : down ? C::press : hot ? C::hover : C::card;
        br = dis ? C::border : hot ? RGB(68, 74, 90) : C::fieldBorder;
        fg = dis ? C::faint : (b.kind == BK_DANGER && hot) ? C::bad : C::text;
        break;
    }
    rrect(dc, full, S(b.kind == BK_PRIMARY ? 8 : 7), bg, br, b.kind == BK_DROP && !g_drop_ok);
    if (focus) {
        RECT fr{1, 1, w - 1, h - 1};
        rrect(dc, fr, S(7), CLR_NONE, b.kind == BK_PRIMARY ? RGB(140, 190, 255) : C::accentHi);
    }
    if (b.kind == BK_DROP) {
        COLORREF ic = g_drop_ok ? C::ok : hot ? C::accentHi : C::dim;
        RECT ir{S(12), 0, S(44), h};
        draw_text(dc, std::wstring(1, b.icon), ir, ui.iconBig, ic, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        draw_text(dc, g_drop_main, {S(52), S(8), w - S(12), h / 2 + S(1)}, ui.semi, dis ? C::faint : C::text, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
        draw_text(dc, g_drop_sub, {S(52), h / 2 + S(1), w - S(12), h - S(6)}, ui.small, g_drop_ok ? C::ok : C::dim, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
        return;
    }
    wchar_t label[128]{};
    GetWindowTextW(di->hwndItem, label, 128);
    HFONT tf = b.kind == BK_PRIMARY ? ui.semi : ui.font;
    if (b.kind == BK_ICON) {
        draw_text(dc, std::wstring(1, b.icon), full, ui.icon, fg, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        return;
    }
    int tw = text_width(dc, label, tf), iw = b.icon ? S(16) + S(8) : 0;
    int x0 = (w - tw - iw) / 2;
    if (b.icon) draw_text(dc, std::wstring(1, b.icon), {x0, 0, x0 + S(16), h}, ui.icon, fg, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    draw_text(dc, label, {x0 + iw, 0, x0 + iw + tw + S(2), h}, tf, fg, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

static void draw_combo_content(HDC dc, RECT lr, HWND cb, int idx, bool sel, bool dis) {
    if (idx < 0) return;
    int len = (int)SendMessageW(cb, CB_GETLBTEXTLEN, idx, 0);
    if (len < 0) return;
    std::wstring s(len + 1, 0);
    SendMessageW(cb, CB_GETLBTEXT, idx, (LPARAM)s.data());
    s.resize(wcslen(s.c_str()));
    size_t t = s.find(L'\t');
    std::wstring main = s.substr(0, t), tag = t == std::wstring::npos ? L"" : s.substr(t + 1);
    bool empty = cb == ui.drives && g_drives.empty();
    RECT tr{lr.left + S(10), lr.top, lr.right - S(10), lr.bottom};
    if (!tag.empty()) {
        int tagw = text_width(dc, tag, ui.small) + S(16);
        int hh = lr.bottom - lr.top;
        RECT pr{lr.right - S(8) - tagw, lr.top + (hh - S(18)) / 2, lr.right - S(8), lr.top + (hh - S(18)) / 2 + S(18)};
        if (cb == ui.version) {
            COLORREF tagc = C::dim;
            if (tag == L"sans SHA-256") tagc = C::bad;
            else if (tag == L"HTTPS" || tag == L"en cache" || tag == L"MEGAcmd") tagc = C::ok;
            else if (tag == L"MEGA manuel" || tag == L"fichier local") tagc = C::warn;
            rrect(dc, pr, S(9), sel ? RGB(36, 56, 90) : RGB(28, 32, 42), CLR_NONE);
            draw_text(dc, tag, pr, ui.small, dis ? C::faint : tagc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        } else draw_text(dc, tag, pr, ui.small, C::dim, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        tr.right = pr.left - S(6);
    }
    draw_text(dc, main, tr, ui.font, (dis || empty) ? C::faint : C::text, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

static void draw_combo_item(DRAWITEMSTRUCT* di) {
    RECT r = di->rcItem;
    bool sel = (di->itemState & ODS_SELECTED) && !(di->itemState & ODS_COMBOBOXEDIT);
    int w = r.right - r.left, h = r.bottom - r.top;
    HDC mdc = CreateCompatibleDC(di->hDC);
    HBITMAP bmp = CreateCompatibleBitmap(di->hDC, std::max(1, w), std::max(1, h));
    HGDIOBJ old = SelectObject(mdc, bmp);
    RECT lr{0, 0, w, h};
    fill(mdc, lr, sel ? C::sel : C::field);
    draw_combo_content(mdc, lr, di->hwndItem, (int)di->itemID, sel, false);
    BitBlt(di->hDC, r.left, r.top, w, h, mdc, 0, 0, SRCCOPY);
    SelectObject(mdc, old);
    DeleteObject(bmp);
    DeleteDC(mdc);
}

static std::map<HWND, bool> g_combo_hot;

static LRESULT CALLBACK ComboProc(HWND h, UINT m, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR) {
    switch (m) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(h, &ps);
        RECT rc;
        GetClientRect(h, &rc);
        {
            MemDC mem(hdc, rc.right, rc.bottom);
            HDC dc = mem.dc;
            fill(dc, rc, C::card);
            bool dis = !IsWindowEnabled(h), open = SendMessageW(h, CB_GETDROPPEDSTATE, 0, 0), focus = GetFocus() == h;
            bool hot = g_combo_hot[h] && !dis;
            rrect(dc, rc, S(7), dis ? C::card : (hot || open) ? RGB(20, 23, 31) : C::field, (open || focus) ? C::accent : hot ? RGB(68, 74, 90) : C::fieldBorder);
            RECT content{rc.left + 1, rc.top + 1, rc.right - S(30), rc.bottom - 1};
            draw_combo_content(dc, content, h, (int)SendMessageW(h, CB_GETCURSEL, 0, 0), false, dis);
            RECT ar{rc.right - S(30), 0, rc.right - S(6), rc.bottom};
            draw_text(dc, L"\xE70D", ar, ui.icon, dis ? C::faint : C::dim, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
        EndPaint(h, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_MOUSEMOVE:
        if (!g_combo_hot[h]) {
            g_combo_hot[h] = true;
            TRACKMOUSEEVENT t{sizeof t, TME_LEAVE, h, 0};
            TrackMouseEvent(&t);
            InvalidateRect(h, nullptr, FALSE);
        }
        break;
    case WM_MOUSELEAVE:
        g_combo_hot[h] = false;
        InvalidateRect(h, nullptr, FALSE);
        break;
    case WM_SETFOCUS:
    case WM_KILLFOCUS:
    case WM_ENABLE:
    case CB_SETCURSEL:
    case CB_RESETCONTENT: {
        LRESULT r = DefSubclassProc(h, m, wp, lp);
        InvalidateRect(h, nullptr, FALSE);
        return r;
    }
    case WM_SETCURSOR:
        if (IsWindowEnabled(h)) {
            SetCursor(LoadCursorW(nullptr, IDC_HAND));
            return TRUE;
        }
        break;
    }
    return DefSubclassProc(h, m, wp, lp);
}

static void draw_driveinfo(DRAWITEMSTRUCT* di) {
    RECT r = di->rcItem;
    int w = r.right - r.left, h = r.bottom - r.top;
    MemDC mem(di->hDC, w, h);
    HDC dc = mem.dc;
    fill(dc, {0, 0, w, h}, C::card);
    const Drive* d = selected_drive();
    if (!d) {
        draw_text(dc, L"Branche une clé USB : elle sera détectée automatiquement.", {0, 0, w, h}, ui.small, C::dim, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        return;
    }
    bool ok = d->fs_ok();
    int cw = text_width(dc, d->fs, ui.small) + S(16);
    RECT chip{0, (h - S(18)) / 2, cw, (h - S(18)) / 2 + S(18)};
    rrect(dc, chip, S(9), ok ? C::okBg : C::badBg, CLR_NONE);
    draw_text(dc, d->fs, chip, ui.small, ok ? C::ok : C::bad, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    std::wstring s = F(L"Disque %lu  ·  %ls  ·  %ls libres", d->disk, d->removable ? L"amovible" : L"externe", human(d->free).c_str());
    if (!ok) s += L"  ·  à formater en exFAT";
    draw_text(dc, s, {cw + S(10), 0, w, h}, ui.small, ok ? C::dim : C::warn, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

static void draw_bar(DRAWITEMSTRUCT* di) {
    RECT r = di->rcItem;
    int w = r.right - r.left, h = r.bottom - r.top;
    MemDC mem(di->hDC, w, h);
    HDC dc = mem.dc;
    fill(dc, {0, 0, w, h}, C::card);
    rrect(dc, {0, 0, w, h}, h / 2, RGB(32, 36, 46), CLR_NONE);
    if (ui.marquee) {
        int seg = w / 4, span = w + seg;
        int x = (ui.phase * S(4)) % span - seg;
        HRGN clip = CreateRectRgn(0, 0, w, h);
        SelectClipRgn(dc, clip);
        rrect(dc, {std::max(0, x), 0, std::min(w, x + seg), h}, h / 2, C::accentHi, CLR_NONE);
        SelectClipRgn(dc, nullptr);
        DeleteObject(clip);
    } else if (ui.bar_pos > 0) {
        int fw = std::max(h, w * ui.bar_pos / 1000);
        Gdiplus::Graphics g(dc);
        g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
        g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);
        Gdiplus::GraphicsPath p;
        round_path(p, 0, 0, (float)fw, (float)h, h / 2.0f);
        COLORREF a = ui.bar_color, b2 = ui.bar_color == C::accent ? C::accentHi : ui.bar_color;
        Gdiplus::LinearGradientBrush lb(Gdiplus::PointF(0, 0), Gdiplus::PointF((float)fw + 1, 0), GC(a), GC(b2));
        g.FillPath(&lb, &p);
    }
}

static LRESULT CALLBACK BtnProc(HWND h, UINT m, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR) {
    switch (m) {
    case WM_MOUSEMOVE: {
        auto& b = g_btn[h];
        if (!b.hot) {
            b.hot = true;
            TRACKMOUSEEVENT t{sizeof t, TME_LEAVE, h, 0};
            TrackMouseEvent(&t);
            InvalidateRect(h, nullptr, FALSE);
        }
        break;
    }
    case WM_MOUSELEAVE:
        g_btn[h].hot = false;
        InvalidateRect(h, nullptr, FALSE);
        break;
    case WM_SETCURSOR:
        if (IsWindowEnabled(h)) {
            SetCursor(LoadCursorW(nullptr, IDC_HAND));
            return TRUE;
        }
        break;
    case WM_LBUTTONDBLCLK:
        return DefSubclassProc(h, WM_LBUTTONDOWN, wp, lp);
    case WM_ERASEBKGND:
        return 1;
    case WM_ENABLE:
        InvalidateRect(h, nullptr, FALSE);
        break;
    }
    return DefSubclassProc(h, m, wp, lp);
}

static HWND mk(const wchar_t* cls, const wchar_t* text, DWORD style, int id, DWORD ex = 0) {
    return CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10, g_hwnd, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
}

static HWND mkbtn(const wchar_t* text, int id, int kind, wchar_t icon) {
    HWND h = mk(WC_BUTTONW, text, BS_OWNERDRAW | WS_TABSTOP, id);
    g_btn[h] = BtnInfo{kind, icon, false};
    SetWindowSubclass(h, BtnProc, 1, 0);
    return h;
}

static void add_tip(HWND ctl, const wchar_t* t) {
    TOOLINFOW ti{};
    ti.cbSize = sizeof ti;
    ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    ti.hwnd = g_hwnd;
    ti.uId = (UINT_PTR)ctl;
    ti.lpszText = (LPWSTR)t;
    SendMessageW(ui.tip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
}

using AllowDarkFn = BOOL(WINAPI*)(HWND, BOOL);
static AllowDarkFn g_allow_dark;

static void dark(HWND h, const wchar_t* theme) {
    if (g_allow_dark) g_allow_dark(h, TRUE);
    SetWindowTheme(h, theme, nullptr);
}

static void init_dark_mode() {
    HMODULE ux = LoadLibraryExW(L"uxtheme.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!ux) return;
    using SetModeFn = int(WINAPI*)(int);
    if (auto set = (SetModeFn)(void*)GetProcAddress(ux, MAKEINTRESOURCEA(135))) set(1);
    g_allow_dark = (AllowDarkFn)(void*)GetProcAddress(ux, MAKEINTRESOURCEA(133));
}

static void create_controls() {
    ui.drives = mk(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS | WS_TABSTOP | WS_VSCROLL, IDC_DRIVES);
    ui.refresh = mkbtn(L"", IDC_REFRESH, BK_ICON, 0xE72C);
    ui.format = mkbtn(L"Formater", IDC_FORMAT, BK_DANGER, 0xE74D);
    ui.eject = mkbtn(L"Éjecter", IDC_EJECT, BK_GHOST, 0xE898);
    ui.driveinfo = mk(WC_STATICW, L"", SS_OWNERDRAW, IDC_DRIVEINFO);
    ui.version = mk(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS | WS_TABSTOP | WS_VSCROLL, IDC_VERSION);
    ui.archives = mkbtn(L"", IDC_ARCHIVES, BK_ICON, 0xE895);
    ui.site = mkbtn(L"", IDC_SITE, BK_ICON, 0xE774);
    ui.cache = mkbtn(L"", IDC_CACHE, BK_ICON, 0xE8B7);
    ui.source = mk(WC_STATICW, L"", SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS, IDC_SOURCE);
    ui.sha = mk(WC_STATICW, L"", SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS, IDC_SHA);
    ui.drop = mkbtn(L"", IDC_LOCAL, BK_DROP, 0xE896);
    ui.status = mk(WC_STATICW, L"Prêt", SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS, IDC_STATUS);
    ui.detail = mk(WC_STATICW, L"", SS_RIGHT | SS_NOPREFIX | SS_ENDELLIPSIS, IDC_DETAIL);
    ui.progress = mk(WC_STATICW, L"", SS_OWNERDRAW, IDC_PROGRESS);
    ui.start = mkbtn(L"Préparer la clé", IDC_START, BK_PRIMARY, 0xE88E);
    ui.cancel = mkbtn(L"Annuler", IDC_CANCEL, BK_GHOST, 0xE711);
    ui.log = mk(WC_EDITW, L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL, IDC_LOG);
    SendMessageW(ui.log, EM_SETLIMITTEXT, 2 * 1024 * 1024, 0);
    SendMessageW(ui.log, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(2, 2));
    for (HWND cb : {ui.drives, ui.version}) {
        dark(cb, L"DarkMode_CFD");
        SetWindowSubclass(cb, ComboProc, 2, 0);
        COMBOBOXINFO ci{sizeof ci};
        if (GetComboBoxInfo(cb, &ci) && ci.hwndList) dark(ci.hwndList, L"DarkMode_Explorer");
    }
    dark(ui.log, L"DarkMode_Explorer");
    ui.tip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX, 0, 0, 0, 0, g_hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
    dark(ui.tip, L"DarkMode_Explorer");
    add_tip(ui.refresh, L"Rechercher les clés USB");
    add_tip(ui.archives, L"Actualiser le catalogue des firmwares");
    add_tip(ui.site, L"Ouvrir l'archive Darthsternie");
    add_tip(ui.cache, L"Ouvrir le dossier de cache");
    add_tip(ui.format, L"Formater la clé en exFAT (efface tout)");
    add_tip(ui.eject, L"Retirer la clé en toute sécurité");
    reset_drop();
}

static void apply_dpi(UINT dpi) {
    ui.dpi = dpi;
    make_fonts();
    layout();
}

static void on_done(DoneInfo* d) {
    std::unique_ptr<DoneInfo> g(d);
    g_busy = false;
    set_marquee(false);
    if (ui.closing) {
        DestroyWindow(g_hwnd);
        return;
    }
    apply_busy();
    if (ui.tb) ui.tb->SetProgressState(g_hwnd, d->kind == 2 ? TBPF_ERROR : TBPF_NOPROGRESS);
    if (d->kind == 0) {
        if (d->job == JOB_IDENT) {
            set_status(L"Prêt");
            set_text(ui.detail, L"");
            set_bar(0);
        } else {
            set_bar(1000, C::ok);
            if (d->job == JOB_PREPARE) {
                set_status(L"Clé prête et vérifiée", C::ok);
                set_text(ui.detail, d->msg);
                log_line(L"Succès : " + d->msg);
                update_fw_info();
                fill_versions();
                if (ask(L"Firmware copié et relu depuis la clé :\n" + d->msg +
                            L"\n\nSur la PS5 : Paramètres › Système › Logiciel système › Mise à jour › Mettre à jour depuis une clé USB.\n\nÉjecter la clé maintenant ?",
                        L"Clé prête", MB_ICONINFORMATION | MB_YESNO) == IDYES) {
                    start_eject();
                    return;
                }
            } else {
                set_status(d->msg, C::ok);
                set_text(ui.detail, L"");
                log_line(d->msg);
            }
        }
    } else if (d->kind == 1) {
        set_status(L"Annulé", C::warn);
        set_bar(0);
        set_text(ui.detail, L"");
        log_line(d->msg);
    } else {
        set_status(L"Échec", C::bad);
        set_bar(1000, C::bad);
        set_text(ui.detail, L"");
        log_line(L"Erreur : " + d->msg);
        ask(d->msg, APP_NAME, MB_ICONERROR);
    }
    if (d->job == JOB_FORMAT || d->job == JOB_EJECT || ui.pending_scan) {
        ui.pending_scan = false;
        scan_drives();
    }
}

static LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    if (ui.tbmsg && msg == ui.tbmsg) {
        if (!ui.tb) CoCreateInstance(CLSID_TaskbarList, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskbarList3, (void**)&ui.tb);
        if (ui.tb) ui.tb->HrInit();
        return 0;
    }
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = h;
        ui.dpi = GetDpiForWindow(h);
        BOOL on = TRUE;
        DwmSetWindowAttribute(h, 20, &on, sizeof on);
        COLORREF cap = C::bg;
        DwmSetWindowAttribute(h, 35, &cap, sizeof cap);
        if (font_exists(L"Segoe UI Variable Text")) ui.uiFont = L"Segoe UI Variable Text";
        if (font_exists(L"Segoe Fluent Icons")) ui.iconFont = L"Segoe Fluent Icons";
        if (font_exists(L"Cascadia Mono")) ui.monoFont = L"Cascadia Mono";
        ui.bgBrush = CreateSolidBrush(C::bg);
        ui.cardBrush = CreateSolidBrush(C::card);
        ui.fieldBrush = CreateSolidBrush(C::field);
        ui.has_mega = !megacmd().empty();
        create_controls();
        apply_dpi(ui.dpi);
        g_catalog = builtin_catalog();
        fill_versions();
        fill_drives();
        apply_busy();
        log_line(std::wstring(APP_NAME) + L" " + APP_VER + L"  ·  cache : " + g_cache);
        log_line(L"Prépare uniquement une clé de mise à jour officielle : ne contourne aucune restriction PS5.");
        scan_drives();
        load_catalog();
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        paint(dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_SIZE:
        layout();
        return 0;
    case WM_GETMINMAXINFO: {
        auto* mm = (MINMAXINFO*)lp;
        RECT r{0, 0, S(500), S(700)};
        AdjustWindowRectExForDpi(&r, WS_OVERLAPPEDWINDOW, FALSE, 0, ui.dpi);
        mm->ptMinTrackSize = {r.right - r.left, r.bottom - r.top};
        return 0;
    }
    case WM_DPICHANGED: {
        auto* r = (RECT*)lp;
        ui.dpi = HIWORD(wp);
        SetWindowPos(h, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
        apply_dpi(ui.dpi);
        return 0;
    }
    case WM_MEASUREITEM: {
        auto* mi = (MEASUREITEMSTRUCT*)lp;
        if (mi->CtlType == ODT_COMBOBOX) mi->itemHeight = mi->itemID == (UINT)-1 ? S(26) : S(28);
        return TRUE;
    }
    case WM_DRAWITEM: {
        auto* di = (DRAWITEMSTRUCT*)lp;
        if (di->CtlType == ODT_BUTTON) draw_button(di);
        else if (di->CtlType == ODT_COMBOBOX) draw_combo_item(di);
        else if (di->hwndItem == ui.driveinfo) draw_driveinfo(di);
        else if (di->hwndItem == ui.progress) draw_bar(di);
        return TRUE;
    }
    case WM_CTLCOLORLISTBOX: {
        HDC dc = (HDC)wp;
        SetBkColor(dc, C::field);
        SetTextColor(dc, C::text);
        return (LRESULT)ui.fieldBrush;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp;
        HWND c = (HWND)lp;
        if (c == ui.log) {
            SetBkColor(dc, C::field);
            SetTextColor(dc, RGB(165, 172, 184));
            return (LRESULT)ui.fieldBrush;
        }
        SetBkColor(dc, C::card);
        COLORREF col = C::dim;
        if (c == ui.status) col = ui.status_color;
        else if (c == ui.sha) col = C::faint;
        SetTextColor(dc, col);
        return (LRESULT)ui.cardBrush;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp), code = HIWORD(wp);
        switch (id) {
        case IDC_DRIVES:
            if (code == CBN_CLOSEUP || code == CBN_DROPDOWN) InvalidateRect(ui.drives, nullptr, FALSE);
            if (code == CBN_SELCHANGE) {
                if (auto d = selected_drive()) g_selected_drive_id = d->id;
                update_drive_info();
            }
            break;
        case IDC_VERSION:
            if (code == CBN_CLOSEUP || code == CBN_DROPDOWN) InvalidateRect(ui.version, nullptr, FALSE);
            if (code == CBN_SELCHANGE) {
                if (auto f = selected_fw()) {
                    g_selected_version = f->version;
                    if (!g_local_version.empty() && g_local_version != f->version) {
                        g_local_path.clear();
                        g_local_version.clear();
                        reset_drop();
                    }
                }
                update_fw_info();
            }
            break;
        case IDC_REFRESH: scan_drives(); break;
        case IDC_ARCHIVES: load_catalog(); break;
        case IDC_SITE: ShellExecuteW(h, L"open", D_ARCHIVE, nullptr, nullptr, SW_SHOWNORMAL); break;
        case IDC_LOCAL: if (!g_busy) choose_local(); break;
        case IDC_START: if (!g_busy) start_prepare(); break;
        case IDC_FORMAT: if (!g_busy) start_format(); break;
        case IDC_EJECT: if (!g_busy) start_eject(); break;
        case IDC_CANCEL:
            if (g_busy) {
                g_cancel = true;
                EnableWindow(ui.cancel, FALSE);
                set_status(L"Annulation…", C::warn);
            }
            break;
        case IDC_CACHE:
            make_dirs(g_cache);
            ShellExecuteW(h, L"open", g_cache.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            break;
        }
        return 0;
    }
    case WM_DROPFILES: {
        HDROP drop = (HDROP)wp;
        wchar_t path[MAX_PATH * 4]{};
        if (DragQueryFileW(drop, 0, path, MAX_PATH * 4)) identify_local(path);
        DragFinish(drop);
        return 0;
    }
    case WM_DEVICECHANGE:
        if (wp == DBT_DEVICEARRIVAL || wp == DBT_DEVICEREMOVECOMPLETE) SetTimer(h, TIMER_DEV, 900, nullptr);
        return TRUE;
    case WM_TIMER:
        if (wp == TIMER_DEV) {
            KillTimer(h, TIMER_DEV);
            scan_drives();
        } else if (wp == TIMER_ANIM) {
            ui.phase++;
            redraw_bar();
        } else if (wp == TIMER_CLOSE) {
            if (!g_busy || ++ui.close_ticks > 60) DestroyWindow(h);
        }
        return 0;
    case WM_LOGMSG: {
        std::unique_ptr<std::wstring> s((std::wstring*)lp);
        log_line(*s);
        return 0;
    }
    case WM_PROG: {
        std::unique_ptr<Prog> p((Prog*)lp);
        if (!g_busy) return 0;
        set_status(p->phase);
        set_text(ui.detail, p->detail);
        set_progress(p->cur, p->total);
        return 0;
    }
    case WM_DRIVES: {
        std::unique_ptr<std::vector<Drive>> v((std::vector<Drive>*)lp);
        g_scanning = false;
        bool changed = v->size() != g_drives.size();
        for (size_t i = 0; !changed && i < v->size(); i++) changed = (*v)[i].id != g_drives[i].id || (*v)[i].fs != g_drives[i].fs || (*v)[i].free != g_drives[i].free;
        if (!g_busy) {
            g_drives = std::move(*v);
            fill_drives();
            if (changed) log_line(F(L"%d clé(s) USB détectée(s)", (int)g_drives.size()));
        }
        apply_busy();
        return 0;
    }
    case WM_CATALOG: {
        std::unique_ptr<Catalog> c((Catalog*)lp);
        g_catalog_loading = false;
        g_catalog = std::move(*c);
        if (!g_busy) fill_versions();
        apply_busy();
        log_line(F(L"Catalogue : %d version(s)", (int)g_catalog.size()));
        return 0;
    }
    case WM_IDENT:
        on_ident((IdentInfo*)lp);
        return 0;
    case WM_DONE:
        on_done((DoneInfo*)lp);
        return 0;
    case WM_CLOSE:
        if (g_busy) {
            if (ask(L"Une opération est en cours. L'annuler et quitter ?", APP_NAME, MB_ICONQUESTION | MB_YESNO) != IDYES) return 0;
            ui.closing = true;
            g_cancel = true;
            ShowWindow(h, SW_HIDE);
            SetTimer(h, TIMER_CLOSE, 100, nullptr);
            return 0;
        }
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        if (ui.tb) ui.tb->Release();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int show) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    INITCOMMONCONTROLSEX icc{sizeof icc, ICC_STANDARD_CLASSES | ICC_BAR_CLASSES};
    InitCommonControlsEx(&icc);
    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR gtoken = 0;
    Gdiplus::GdiplusStartup(&gtoken, &gsi, nullptr);
    init_dark_mode();

    wchar_t exe[MAX_PATH * 2]{};
    GetModuleFileNameW(nullptr, exe, MAX_PATH * 2);
    g_exe_dir = exe;
    g_exe_dir = g_exe_dir.substr(0, g_exe_dir.find_last_of(L"\\/"));
    PWSTR la = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &la))) {
        g_cache = std::wstring(la) + L"\\PS5USBPrep";
        CoTaskMemFree(la);
    } else g_cache = g_exe_dir + L"\\cache";
    http_init();
    ui.tbmsg = RegisterWindowMessageW(L"TaskbarButtonCreated");

    WNDCLASSEXW wc{sizeof wc};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(1));
    wc.hIconSm = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"PS5USBPrepWnd";
    RegisterClassExW(&wc);

    std::wstring title = std::wstring(APP_NAME) + L" " + APP_VER;
    HWND h = CreateWindowExW(WS_EX_CONTROLPARENT, wc.lpszClassName, title.c_str(), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 540, 780, nullptr, nullptr, inst, nullptr);
    if (!h) return 1;
    RECT r{0, 0, S(520), S(790)};
    AdjustWindowRectExForDpi(&r, WS_OVERLAPPEDWINDOW, FALSE, 0, ui.dpi);
    HMONITOR mon = MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi{sizeof mi};
    GetMonitorInfoW(mon, &mi);
    int ww = r.right - r.left, wh = std::min<int>(r.bottom - r.top, mi.rcWork.bottom - mi.rcWork.top);
    SetWindowPos(h, nullptr, mi.rcWork.left + (mi.rcWork.right - mi.rcWork.left - ww) / 2, mi.rcWork.top + (mi.rcWork.bottom - mi.rcWork.top - wh) / 2, ww, wh, SWP_NOZORDER);
    ShowWindow(h, show);
    UpdateWindow(h);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0) {
        if (IsDialogMessageW(h, &m)) continue;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    if (g_session) WinHttpCloseHandle(g_session);
    Gdiplus::GdiplusShutdown(gtoken);
    CoUninitialize();
    return 0;
}
