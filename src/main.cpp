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
static const wchar_t* APP_VER = L"2.2";
static const wchar_t* UA = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) PSD/2.2";
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
#include <dbghelp.h>
#include <cmath>
#include <exception>

namespace C {
const COLORREF bg = RGB(17, 19, 25);
const COLORREF caption = RGB(13, 15, 20);
const COLORREF border = RGB(40, 44, 55);
const COLORREF field = RGB(24, 27, 35);
const COLORREF fieldBorder = RGB(46, 51, 64);
const COLORREF hover = RGB(34, 38, 49);
const COLORREF press = RGB(28, 32, 41);
const COLORREF text = RGB(234, 236, 240);
const COLORREF dim = RGB(148, 155, 168);
const COLORREF faint = RGB(96, 103, 116);
const COLORREF accent = RGB(0, 112, 209);
const COLORREF accentHi = RGB(30, 136, 235);
const COLORREF accentLo = RGB(0, 90, 172);
const COLORREF section = RGB(86, 160, 245);
const COLORREF sel = RGB(26, 44, 74);
const COLORREF ok = RGB(52, 199, 120);
const COLORREF okBg = RGB(20, 52, 38);
const COLORREF bad = RGB(240, 82, 87);
const COLORREF badBg = RGB(66, 25, 29);
const COLORREF warn = RGB(245, 170, 50);
const COLORREF closeHot = RGB(196, 43, 28);
}

enum { IDC_SELECT = 200, IDC_LOGBTN, IDC_MIN, IDC_MAX, IDC_CLOSE, IDC_FILE, IDC_SCROLL, IDC_DEV };
enum BtnKind { BK_PRIMARY, BK_GHOST, BK_DANGER, BK_ICON, BK_FIELD, BK_CAP, BK_CAPCLOSE };
struct BtnInfo {
    int kind = BK_GHOST;
    wchar_t icon = 0;
    bool hot = false;
    bool active = false;
};

struct Label {
    RECT r;
    std::wstring text;
    bool section;
};

struct Ui {
    HWND drives, refresh, driveinfo, version, archives, site, cache, sha, file, select, progress, detail;
    HWND start, cancel, format, eject, logbtn, devbtn, log, scroll, tip, bmin, bmax, bclose;
    HFONT font = nullptr, semi = nullptr, title = nullptr, small = nullptr, smallSemi = nullptr, mono = nullptr, icon = nullptr, iconCap = nullptr;
    HBRUSH bgBrush = nullptr, fieldBrush = nullptr;
    HICON appIcon = nullptr;
    std::wstring uiFont = L"Segoe UI", iconFont = L"Segoe MDL2 Assets", monoFont = L"Consolas";
    std::vector<Label> labels;
    RECT shaField{}, logField{};
    int captionH = 0, footerTop = 0, contentH = 0;
    UINT dpi = 96;
    ITaskbarList3* tb = nullptr;
    UINT tbmsg = 0;
    std::wstring status = L"Prêt";
    COLORREF status_color = C::text;
    COLORREF bar_color = C::accent;
    int bar_pos = 0;
    bool marquee = false;
    int phase = 0;
    bool closing = false;
    int close_ticks = 0;
    bool pending_scan = false;
    bool has_mega = false;
    bool log_visible = false;
    bool win11 = false;
} ui;

enum { TIMER_ANIM = 3 };
static const int LOG_H = 170;

static std::map<HWND, BtnInfo> g_btn;
static Catalog g_catalog;
static std::vector<std::wstring> g_versions;
static std::vector<Drive> g_drives;
static std::wstring g_local_path, g_local_version;
static std::wstring g_selected_version = L"13.60.00";
static std::wstring g_selected_drive_id;
static std::wstring g_file_text;
static bool g_file_ok = false;

static int S(int v) { return MulDiv(v, (int)ui.dpi, 96); }
static Gdiplus::Color GC(COLORREF c, BYTE a = 255) { return Gdiplus::Color(a, GetRValue(c), GetGValue(c), GetBValue(c)); }

static void round_path(Gdiplus::GraphicsPath& p, float x, float y, float w, float h, float r) {
    float d = std::min(r * 2, std::min(w, h));
    if (d <= 0) {
        p.AddRectangle(Gdiplus::RectF(x, y, w, h));
        return;
    }
    p.AddArc(x, y, d, d, 180, 90);
    p.AddArc(x + w - d, y, d, d, 270, 90);
    p.AddArc(x + w - d, y + h - d, d, d, 0, 90);
    p.AddArc(x, y + h - d, d, d, 90, 90);
    p.CloseFigure();
}

static void rrect(HDC dc, const RECT& r, int rad, COLORREF fillc, COLORREF stroke) {
    Gdiplus::Graphics g(dc);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);
    float x = (float)r.left, y = (float)r.top, w = (float)(r.right - r.left), h = (float)(r.bottom - r.top);
    if (fillc != CLR_NONE) {
        Gdiplus::GraphicsPath p;
        round_path(p, x, y, w, h, (float)rad);
        Gdiplus::SolidBrush b(GC(fillc));
        g.FillPath(&b, &p);
    }
    if (stroke != CLR_NONE) {
        Gdiplus::GraphicsPath p;
        round_path(p, x + 0.5f, y + 0.5f, w - 1, h - 1, (float)rad);
        Gdiplus::Pen pen(GC(stroke), 1.0f);
        g.DrawPath(&pen, &p);
    }
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


static void icon(HDC dc, wchar_t id, RECT r, COLORREF c, int box) {
    Gdiplus::Graphics g(dc);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);
    float w = (float)(r.right - r.left), h = (float)(r.bottom - r.top);
    float s = std::min((float)box, std::min(w, h));
    float k = s / 24.0f, ox = r.left + (w - s) / 2, oy = r.top + (h - s) / 2;
    Gdiplus::Pen pen(GC(c), std::max(1.25f, 2.0f * k));
    pen.SetLineCap(Gdiplus::LineCapRound, Gdiplus::LineCapRound, Gdiplus::DashCapRound);
    pen.SetLineJoin(Gdiplus::LineJoinRound);
    auto P = [&](float x, float y) { return Gdiplus::PointF(ox + x * k, oy + y * k); };
    auto line = [&](float a, float b, float c2, float d) { g.DrawLine(&pen, P(a, b), P(c2, d)); };
    auto poly = [&](std::initializer_list<float> v, bool closed) {
        std::vector<Gdiplus::PointF> pts;
        for (auto it = v.begin(); it != v.end(); it += 2) pts.push_back(P(*it, *(it + 1)));
        if (closed) g.DrawPolygon(&pen, pts.data(), (INT)pts.size());
        else g.DrawLines(&pen, pts.data(), (INT)pts.size());
    };
    auto arc = [&](float cx, float cy, float rad, float a0, float sw) { g.DrawArc(&pen, ox + (cx - rad) * k, oy + (cy - rad) * k, 2 * rad * k, 2 * rad * k, a0, sw); };
    auto circ = [&](float cx, float cy, float rad) { g.DrawEllipse(&pen, ox + (cx - rad) * k, oy + (cy - rad) * k, 2 * rad * k, 2 * rad * k); };
    auto box2 = [&](float x, float y, float bw, float bh, float rr) {
        Gdiplus::GraphicsPath p;
        round_path(p, ox + x * k, oy + y * k, bw * k, bh * k, rr * k);
        g.DrawPath(&pen, &p);
    };
    auto dot = [&](float x, float y) { line(x, y, x + 0.01f, y); };
    switch (id) {
    case 0xE72C: arc(12, 12, 9, 0, 315); line(18.36f, 5.64f, 21, 8); poly({21, 3, 21, 8, 16, 8}, false); break;
    case 0xE895:
        arc(12, 12, 9, 180, 135); line(18.36f, 5.64f, 21, 8); poly({21, 3, 21, 8, 16, 8}, false);
        arc(12, 12, 9, 0, 135); line(5.64f, 18.36f, 3, 16); poly({8, 16, 3, 16, 3, 21}, false);
        break;
    case 0xE774: circ(12, 12, 10); line(2, 12, 22, 12); g.DrawEllipse(&pen, ox + 8 * k, oy + 2 * k, 8 * k, 20 * k); break;
    case 0xE838:
    case 0xE8B7: poly({2, 6, 2, 18, 4, 20, 20, 20, 22, 18, 22, 9, 20, 7, 12, 7, 10, 4, 4, 4}, true); break;
    case 0xE896: line(12, 3, 12, 15); poly({7, 10, 12, 15, 17, 10}, false); poly({21, 15, 21, 19, 19, 21, 5, 21, 3, 19, 3, 15}, false); break;
    case 0xE74E: line(12, 15, 12, 3); poly({7, 8, 12, 3, 17, 8}, false); poly({21, 15, 21, 19, 19, 21, 5, 21, 3, 19, 3, 15}, false); break;
    case 0xE73E: poly({20, 6, 9, 17, 4, 12}, false); break;
    case 0xE88E: poly({13, 2, 4, 14, 12, 14, 11, 22, 20, 10, 12, 10}, true); break;
    case 0xE898: poly({12, 4, 20, 14, 4, 14}, true); line(4, 19, 20, 19); break;
    case 0xE74D:
        line(3, 6, 21, 6); poly({19, 6, 19, 20, 17, 22, 7, 22, 5, 20, 5, 6}, false); poly({8, 6, 8, 4, 10, 2, 14, 2, 16, 4, 16, 6}, false);
        line(10, 11, 10, 17); line(14, 11, 14, 17);
        break;
    case 0xE8BB: line(18, 6, 6, 18); line(6, 6, 18, 18); break;
    case 0xE921: line(5, 12, 19, 12); break;
    case 0xE922: box2(5, 5, 14, 14, 1.5f); break;
    case 0xE923: box2(4, 8, 12, 12, 1.5f); poly({8, 8, 8, 5, 9, 4, 19, 4, 20, 5, 20, 15, 19, 16, 16, 16}, false); break;
    case 0xE70D: poly({6, 9, 12, 15, 18, 9}, false); break;
    case 0xE81C: box2(2, 4, 20, 16, 2); poly({6, 9, 9, 12, 6, 15}, false); line(12, 15, 17, 15); break;
    case 0xEC7A: poly({16, 18, 22, 12, 16, 6}, false); poly({8, 6, 2, 12, 8, 18}, false); break;
    case 0xE7BA: poly({12, 3, 22, 20, 2, 20}, true); line(12, 9, 12, 13); dot(12, 17); break;
    case 0xE943: poly({7.86f, 2, 16.14f, 2, 22, 7.86f, 22, 16.14f, 16.14f, 22, 7.86f, 22, 2, 16.14f, 2, 7.86f}, true); line(12, 8, 12, 12); dot(12, 16); break;
    case 0xE964:
        box2(5, 5, 14, 14, 2); box2(9, 9, 6, 6, 1);
        line(9, 2, 9, 5); line(15, 2, 15, 5); line(9, 19, 9, 22); line(15, 19, 15, 22);
        line(2, 9, 5, 9); line(2, 15, 5, 15); line(19, 9, 22, 9); line(19, 15, 22, 15);
        break;
    case 0xE81E: poly({12, 2, 22, 7, 12, 12, 2, 7}, true); poly({2, 12, 12, 17, 22, 12}, false); poly({2, 17, 12, 22, 22, 17}, false); break;
    case 0xE9D9: poly({22, 12, 18, 12, 15, 21, 9, 3, 6, 12, 2, 12}, false); break;
    case 0xE7F4: box2(2, 3, 20, 14, 2); line(8, 21, 16, 21); line(12, 17, 12, 21); break;
    case 0xE8A5: poly({14, 2, 6, 2, 4, 4, 4, 20, 6, 22, 18, 22, 20, 20, 20, 8}, true); poly({14, 2, 14, 8, 20, 8}, false); line(8, 13, 16, 13); line(8, 17, 14, 17); break;
    case 0xE894: circ(12, 12, 10); line(15, 9, 9, 15); line(9, 9, 15, 15); break;
    default: circ(12, 12, 3); break;
    }
}

struct MemDC {
    HDC dst, dc;
    HBITMAP bmp;
    HGDIOBJ old;
    int x, y, w, h;
    MemDC(HDC d, int w_, int h_, int x_ = 0, int y_ = 0) : dst(d), x(x_), y(y_), w(w_), h(h_) {
        dc = CreateCompatibleDC(d);
        bmp = CreateCompatibleBitmap(d, std::max(1, w), std::max(1, h));
        old = SelectObject(dc, bmp);
    }
    ~MemDC() {
        BitBlt(dst, x, y, w, h, dc, 0, 0, SRCCOPY);
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

static std::wstring g_log_mirror;
static HWND g_dev_log = nullptr;

static void append_edit(HWND e, const std::wstring& line) {
    int len = GetWindowTextLengthW(e);
    if (len > 1800000) {
        SendMessageW(e, EM_SETSEL, 0, len / 2);
        SendMessageW(e, EM_REPLACESEL, FALSE, (LPARAM)L"");
        len = GetWindowTextLengthW(e);
    }
    SendMessageW(e, EM_SETSEL, len, len);
    SendMessageW(e, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
    SendMessageW(e, EM_SCROLLCARET, 0, 0);
}

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
    g_log_mirror += line;
    if (g_log_mirror.size() > 256 * 1024) g_log_mirror.erase(0, g_log_mirror.size() - 192 * 1024);
    append_edit(ui.log, line);
    if (g_dev_log) append_edit(g_dev_log, line);
}

static void redraw_bar() { InvalidateRect(ui.progress, nullptr, FALSE); }

static void set_status(const std::wstring& s, COLORREF c = C::text) {
    ui.status = s;
    ui.status_color = c;
    redraw_bar();
}

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

static void redraw_footer() {
    RECT rc;
    GetClientRect(g_hwnd, &rc);
    RECT f{0, ui.footerTop, rc.right, rc.bottom};
    InvalidateRect(g_hwnd, &f, FALSE);
}

static void update_drive_info() {
    InvalidateRect(ui.driveinfo, nullptr, FALSE);
    redraw_footer();
}

static void update_fw_info() {
    const Firmware* f = selected_fw();
    if (!f) return;
    if (!g_local_path.empty() && g_local_version == f->version) {
        g_file_ok = true;
        g_btn[ui.file].icon = 0xE73E;
        g_file_text = g_local_path.substr(g_local_path.find_last_of(L"\\/") + 1) + L"   ·   identifié, SHA-256 conforme";
    } else {
        g_file_ok = false;
        g_btn[ui.file].icon = 0xE896;
        if (in_cache(*f)) g_file_text = L"Déjà téléchargé (cache local)";
        else if (!f->direct.empty()) g_file_text = L"Téléchargement automatique (HTTPS)";
        else if (!f->mega.empty()) g_file_text = mega_auto(*f) ? L"Téléchargement automatique (MEGAcmd)" : L"Sur MEGA : télécharge-le puis sélectionne-le";
        else g_file_text = L"Aucun lien : sélectionne ou glisse un .PUP";
        if (f->size) g_file_text += L"   ·   " + human(f->size);
    }
    InvalidateRect(ui.file, nullptr, FALSE);
    set_text(ui.sha, is_hex(f->sha256, 64) ? W(f->sha256) : std::wstring(L"inconnu — copie bloquée"));
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
    redraw_footer();
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
    for (HWND h : {ui.drives, ui.version, ui.file, ui.select, ui.cache}) EnableWindow(h, !b);
    EnableWindow(ui.refresh, !b && !g_scanning);
    EnableWindow(ui.archives, !b && !g_catalog_loading);
    EnableWindow(ui.start, !b && has);
    EnableWindow(ui.format, !b && has);
    EnableWindow(ui.eject, !b && has);
    EnableWindow(ui.cancel, b);
    DragAcceptFiles(g_hwnd, !b);
    set_text(ui.start, b ? L"En cours…" : L"Préparer");
    InvalidateRect(ui.start, nullptr, FALSE);
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
            log_line(L"PUP local identifié : firmware " + kv.first);
            return;
        }
    }
    g_local_path.clear();
    g_local_version.clear();
    update_fw_info();
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
            run_job(JOB_FORMAT, [d]() { format_drive(d); return std::wstring(L"Clé formatée en exFAT. Relance « Préparer »."); });
        return;
    }
    bool use_local = !g_local_path.empty() && g_local_version == fw.version;
    if (use_local && !file_exists(g_local_path)) {
        ask(L"Le fichier local n'existe plus.", APP_NAME, MB_ICONERROR);
        g_local_path.clear();
        g_local_version.clear();
        update_fw_info();
        return;
    }
    std::wstring cached = cache_path(fw);
    bool have_cache = in_cache(fw);
    if (!use_local && !have_cache && fw.direct.empty() && !mega_auto(fw)) {
        if (!fw.mega.empty()) {
            if (ask(L"Cette version n'est disponible que sur MEGA.\n\nOuvrir le lien dans le navigateur ? Une fois téléchargé, sélectionne ou glisse le .PUP dans la fenêtre.\n(Ou installe MEGAcmd pour le téléchargement automatique.)", APP_NAME,
                    MB_ICONINFORMATION | MB_YESNO) == IDYES)
                ShellExecuteW(g_hwnd, L"open", fw.mega.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        } else ask(L"Aucun lien pour cette version. Télécharge le PUP puis sélectionne-le.", APP_NAME, MB_ICONINFORMATION);
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
    for (HFONT f : {ui.font, ui.semi, ui.title, ui.small, ui.smallSemi, ui.mono, ui.icon, ui.iconCap})
        if (f) DeleteObject(f);
    ui.font = mkfont(ui.uiFont, 9, FW_NORMAL);
    ui.semi = mkfont(ui.uiFont, 9, FW_SEMIBOLD);
    ui.title = mkfont(ui.uiFont, 10, FW_SEMIBOLD);
    ui.small = mkfont(ui.uiFont, 8, FW_NORMAL);
    ui.smallSemi = mkfont(ui.uiFont, 8, FW_BOLD);
    ui.mono = mkfont(ui.monoFont, 8, FW_NORMAL);
    ui.icon = mkfont(ui.iconFont, 9, FW_NORMAL);
    ui.iconCap = mkfont(ui.iconFont, 7, FW_NORMAL);
    EnumChildWindows(g_hwnd, [](HWND c, LPARAM) -> BOOL { SendMessageW(c, WM_SETFONT, (WPARAM)ui.font, TRUE); return TRUE; }, 0);
    SendMessageW(ui.sha, WM_SETFONT, (WPARAM)ui.mono, TRUE);
    SendMessageW(ui.log, WM_SETFONT, (WPARAM)ui.mono, TRUE);
    SendMessageW(ui.detail, WM_SETFONT, (WPARAM)ui.small, TRUE);
    for (HWND cb : {ui.drives, ui.version}) {
        SendMessageW(cb, CB_SETITEMHEIGHT, (WPARAM)-1, S(26));
        SendMessageW(cb, CB_SETITEMHEIGHT, 0, S(28));
    }
    if (ui.appIcon) DestroyIcon(ui.appIcon);
    ui.appIcon = (HICON)LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1), IMAGE_ICON, S(20), S(20), 0);
}

static bool sb_update();

static int content_height(bool with_log) {
    int h = S(42) + S(10);
    h += S(30) + S(18) + S(32) + S(10) + S(18) + S(30) + S(14);
    h += S(30) + S(18) + S(32) + S(10) + S(18) + S(30) + S(10) + S(18) + S(28) + S(14);
    h += S(30) + S(30) + S(22) + S(10);
    h += S(34) + S(14);
    if (with_log) h += S(LOG_H);
    h += S(28);
    return h;
}

static void layout() {
    RECT rc;
    GetClientRect(g_hwnd, &rc);
    int W = rc.right, m = S(18), cw = W - 2 * m, x = m;
    ui.captionH = S(42);
    ui.labels.clear();
    auto place = [](HWND h, int px, int py, int w, int hh) { MoveWindow(h, px, py, w, hh, FALSE); };
    int capw = S(46), caph = S(32);
    place(ui.bclose, W - capw, 0, capw, caph);
    place(ui.bmax, W - 2 * capw, 0, capw, caph);
    place(ui.bmin, W - 3 * capw, 0, capw, caph);
    int y = ui.captionH + S(10);
    auto section = [&](const wchar_t* t) {
        ui.labels.push_back({{x, y, x + cw, y + S(22)}, t, true});
        y += S(30);
    };
    auto label = [&](const wchar_t* t, int lx, int lw) { ui.labels.push_back({{lx, y, lx + lw, y + S(16)}, t, false}); };
    int fh = S(30), gap = S(8);

    section(L"Périphérique");
    label(L"Clé USB", x, cw);
    y += S(18);
    place(ui.drives, x, y, cw - S(30) - gap, S(300));
    place(ui.refresh, x + cw - S(30), y, S(30), fh);
    y += S(32) + S(10);
    label(L"Système de fichiers", x, cw / 2);
    label(L"Espace libre", x + cw / 2 + gap / 2, cw / 2);
    y += S(18);
    place(ui.driveinfo, x, y, cw, fh);
    y += S(30) + S(14);

    section(L"Firmware");
    label(L"Version", x, cw);
    y += S(18);
    place(ui.version, x, y, cw - 2 * S(30) - 2 * gap, S(300));
    place(ui.archives, x + cw - 2 * S(30) - gap, y, S(30), fh);
    place(ui.site, x + cw - S(30), y, S(30), fh);
    y += S(32) + S(10);
    label(L"Fichier PUP", x, cw);
    y += S(18);
    place(ui.file, x, y, cw - S(100) - gap, fh);
    place(ui.select, x + cw - S(100), y, S(100), fh);
    y += S(30) + S(10);
    label(L"Empreinte SHA-256", x, cw);
    y += S(18);
    ui.shaField = {x, y, x + cw, y + S(28)};
    place(ui.sha, x + S(10), y + S(7), cw - S(20), S(16));
    y += S(28) + S(14);

    section(L"Statut");
    place(ui.progress, x, y, cw, S(30));
    y += S(30) + S(4);
    place(ui.detail, x, y, cw, S(18));
    y += S(18) + S(10);

    int bh = S(34), ib = S(34);
    place(ui.logbtn, x, y, ib, bh);
    place(ui.cache, x + (ib + S(6)), y, ib, bh);
    place(ui.format, x + 2 * (ib + S(6)), y, ib, bh);
    place(ui.eject, x + 3 * (ib + S(6)), y, ib, bh);
    place(ui.devbtn, x + 4 * (ib + S(6)), y, ib, bh);
    place(ui.cancel, x + cw - S(96), y, S(96), bh);
    place(ui.start, x + cw - S(96) - gap - S(124), y, S(124), bh);
    y += bh + S(14);

    ui.footerTop = rc.bottom - S(28);
    if (ui.log_visible) {
        ui.logField = {x, y, x + cw, std::max(y + S(80), ui.footerTop - S(10))};
        int lw = ui.logField.right - ui.logField.left, lh = ui.logField.bottom - ui.logField.top;
        place(ui.log, ui.logField.left + S(10), ui.logField.top + S(8), lw - S(10) - S(18), lh - S(14));
        place(ui.scroll, ui.logField.right - S(14), ui.logField.top + S(4), S(12), lh - S(8));
    }
    ShowWindow(ui.log, ui.log_visible ? SW_SHOW : SW_HIDE);
    ShowWindow(ui.scroll, ui.log_visible ? SW_SHOW : SW_HIDE);
    g_btn[ui.logbtn].active = ui.log_visible;
    RedrawWindow(g_hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN);
    if (ui.scroll) sb_update();
}

static void paint(HDC hdc) {
    RECT rc;
    GetClientRect(g_hwnd, &rc);
    MemDC mem(hdc, rc.right, rc.bottom);
    HDC dc = mem.dc;
    fill(dc, rc, C::bg);
    fill(dc, {0, 0, rc.right, ui.captionH}, C::caption);
    fill(dc, {0, ui.captionH - 1, rc.right, ui.captionH}, C::border);
    int m = S(14);
    if (ui.appIcon) DrawIconEx(dc, m, (ui.captionH - S(20)) / 2, ui.appIcon, S(20), S(20), 0, nullptr, DI_NORMAL);
    int tx = m + S(30);
    draw_text(dc, L"PSD", {tx, 0, rc.right, ui.captionH}, ui.title, C::text, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    tx += text_width(dc, L"PSD", ui.title) + S(10);
    draw_text(dc, L"PS5 USB Prep", {tx, 0, rc.right - S(150), ui.captionH}, ui.small, C::faint, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    for (auto& l : ui.labels) {
        if (l.section) {
            int w = text_width(dc, l.text, ui.semi);
            draw_text(dc, l.text, l.r, ui.semi, C::text, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            int ly = (l.r.top + l.r.bottom) / 2;
            Gdiplus::Graphics g(dc);
            g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
            Gdiplus::LinearGradientBrush lb(Gdiplus::PointF((float)l.r.left + w + S(10), 0), Gdiplus::PointF((float)l.r.right + 1, 0), GC(C::accent), GC(C::bg));
            g.FillRectangle(&lb, (float)l.r.left + w + S(10), (float)ly, (float)(l.r.right - l.r.left - w - S(10)), 1.0f);
        } else draw_text(dc, l.text, l.r, ui.small, C::dim, DT_LEFT | DT_TOP | DT_SINGLELINE);
    }
    rrect(dc, ui.shaField, S(6), C::field, C::fieldBorder);
    if (ui.log_visible) rrect(dc, ui.logField, S(8), C::field, C::fieldBorder);

    fill(dc, {0, ui.footerTop, rc.right, rc.bottom}, C::caption);
    fill(dc, {0, ui.footerTop, rc.right, ui.footerTop + 1}, C::border);
    std::wstring foot = F(L"%d clé(s) USB détectée(s)   ·   %d firmware(s) au catalogue", (int)g_drives.size(), (int)g_catalog.size());
    draw_text(dc, foot, {S(18), ui.footerTop, rc.right - S(80), rc.bottom}, ui.small, C::faint, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    draw_text(dc, std::wstring(L"v") + APP_VER, {0, ui.footerTop, rc.right - S(18), rc.bottom}, ui.small, C::faint, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    if (!ui.win11 && !IsZoomed(g_hwnd)) rrect(dc, {0, 0, rc.right, rc.bottom}, S(8), CLR_NONE, C::border);
}

static void draw_button(DRAWITEMSTRUCT* di) {
    auto& b = g_btn[di->hwndItem];
    RECT r = di->rcItem;
    int w = r.right - r.left, h = r.bottom - r.top;
    MemDC mem(di->hDC, w, h);
    HDC dc = mem.dc;
    RECT full{0, 0, w, h};
    bool cap = b.kind == BK_CAP || b.kind == BK_CAPCLOSE;
    fill(dc, full, cap ? C::caption : C::bg);
    bool dis = di->itemState & ODS_DISABLED, down = di->itemState & ODS_SELECTED;
    bool focus = (di->itemState & ODS_FOCUS) && !(di->itemState & ODS_NOFOCUSRECT);
    bool hot = b.hot && !dis;
    if (cap) {
        bool closeHot = b.kind == BK_CAPCLOSE && (hot || down);
        if (closeHot) fill(dc, full, down ? RGB(150, 32, 22) : C::closeHot);
        else if (hot || down) fill(dc, full, down ? C::press : C::hover);
        wchar_t g = b.icon;
        if (di->hwndItem == ui.bmax) g = IsZoomed(g_hwnd) ? 0xE923 : 0xE922;
        icon(dc, g, full, closeHot ? RGB(255, 255, 255) : C::text, S(14));
        return;
    }
    COLORREF bgc, br, fg;
    switch (b.kind) {
    case BK_PRIMARY:
        bgc = dis ? RGB(34, 39, 50) : down ? C::accentLo : hot ? C::accentHi : C::accent;
        br = CLR_NONE;
        fg = dis ? C::faint : RGB(255, 255, 255);
        break;
    case BK_FIELD:
        bgc = dis ? C::bg : hot ? RGB(28, 32, 42) : C::field;
        br = g_file_ok ? RGB(36, 110, 76) : hot ? RGB(68, 74, 90) : C::fieldBorder;
        fg = C::text;
        break;
    default:
        bgc = b.active ? C::sel : dis ? C::bg : down ? C::press : hot ? C::hover : C::field;
        br = b.active ? C::accent : dis ? C::border : hot ? RGB(68, 74, 90) : C::fieldBorder;
        fg = dis ? C::faint : (b.kind == BK_DANGER && hot) ? C::bad : b.active ? C::accentHi : C::text;
        break;
    }
    rrect(dc, full, S(6), bgc, br);
    if (focus) {
        RECT fr{1, 1, w - 1, h - 1};
        rrect(dc, fr, S(6), CLR_NONE, b.kind == BK_PRIMARY ? RGB(140, 190, 255) : C::accentHi);
    }
    if (b.kind == BK_FIELD) {
        COLORREF ic = g_file_ok ? C::ok : C::dim;
        icon(dc, b.icon, {S(8), 0, S(30), h}, dis ? C::faint : ic, S(16));
        draw_text(dc, g_file_text, {S(34), 0, w - S(10), h}, ui.font, dis ? C::faint : (g_file_ok ? C::ok : C::text), DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        return;
    }
    wchar_t label[128]{};
    GetWindowTextW(di->hwndItem, label, 128);
    if (b.kind == BK_ICON || !label[0]) {
        icon(dc, b.icon, full, fg, S(16));
        return;
    }
    HFONT tf = b.kind == BK_PRIMARY ? ui.semi : ui.font;
    int tw = text_width(dc, label, tf), iw = b.icon ? S(16) + S(8) : 0;
    int x0 = (w - tw - iw) / 2;
    if (b.icon) icon(dc, b.icon, {x0, 0, x0 + S(16), h}, fg, S(16));
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
            rrect(dc, pr, S(9), sel ? RGB(36, 56, 90) : RGB(32, 36, 47), CLR_NONE);
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
    MemDC mem(di->hDC, w, h, r.left, r.top);
    RECT lr{0, 0, w, h};
    fill(mem.dc, lr, sel ? C::sel : C::field);
    draw_combo_content(mem.dc, lr, di->hwndItem, (int)di->itemID, sel, false);
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
            fill(dc, rc, C::bg);
            bool dis = !IsWindowEnabled(h), open = SendMessageW(h, CB_GETDROPPEDSTATE, 0, 0), focus = GetFocus() == h;
            bool hot = g_combo_hot[h] && !dis;
            rrect(dc, rc, S(6), dis ? C::bg : (hot || open) ? RGB(28, 32, 42) : C::field, (open || focus) ? C::accent : hot ? RGB(68, 74, 90) : C::fieldBorder);
            RECT content{rc.left + 1, rc.top + 1, rc.right - S(30), rc.bottom - 1};
            draw_combo_content(dc, content, h, (int)SendMessageW(h, CB_GETCURSEL, 0, 0), false, dis);
            RECT ar{rc.right - S(30), 0, rc.right - S(6), rc.bottom};
            icon(dc, 0xE70D, ar, dis ? C::faint : C::dim, S(14));
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

static void draw_field_box(HDC dc, RECT r, const std::wstring& txt, COLORREF col, const std::wstring& chip, bool chip_ok) {
    rrect(dc, r, S(6), C::field, C::fieldBorder);
    int x = r.left + S(10);
    if (!chip.empty()) {
        int cw = text_width(dc, chip, ui.smallSemi) + S(16);
        int hh = r.bottom - r.top;
        RECT c{x - S(4), r.top + (hh - S(18)) / 2, x - S(4) + cw, r.top + (hh - S(18)) / 2 + S(18)};
        rrect(dc, c, S(9), chip_ok ? C::okBg : C::badBg, CLR_NONE);
        draw_text(dc, chip, c, ui.smallSemi, chip_ok ? C::ok : C::bad, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        x = c.right + S(8);
    }
    draw_text(dc, txt, {x, r.top, r.right - S(8), r.bottom}, ui.font, col, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

static void draw_driveinfo(DRAWITEMSTRUCT* di) {
    RECT r = di->rcItem;
    int w = r.right - r.left, h = r.bottom - r.top, gap = S(8);
    MemDC mem(di->hDC, w, h);
    HDC dc = mem.dc;
    fill(dc, {0, 0, w, h}, C::bg);
    RECT a{0, 0, w / 2 - gap / 2, h}, b{w / 2 + gap / 2, 0, w, h};
    const Drive* d = selected_drive();
    if (!d) {
        draw_field_box(dc, a, L"—", C::faint, L"", false);
        draw_field_box(dc, b, L"—", C::faint, L"", false);
        return;
    }
    bool ok = d->fs_ok();
    draw_field_box(dc, a, ok ? (d->removable ? L"amovible" : L"disque externe") : L"à formater en exFAT", ok ? C::dim : C::warn, d->fs, ok);
    double pct = d->size ? 100.0 * (double)(d->size - std::min(d->size, d->free)) / (double)d->size : 0;
    draw_field_box(dc, b, human(d->free) + L"  /  " + human(d->size), C::text, L"", false);
    int bw = S(44), bx = b.right - S(10) - bw, by = (h - S(4)) / 2;
    rrect(dc, {bx, by, bx + bw, by + S(4)}, S(2), RGB(40, 45, 57), CLR_NONE);
    rrect(dc, {bx, by, bx + std::max(S(4), (int)(bw * pct / 100)), by + S(4)}, S(2), pct > 90 ? C::warn : C::accentHi, CLR_NONE);
}

static void draw_bar(DRAWITEMSTRUCT* di) {
    RECT r = di->rcItem;
    int w = r.right - r.left, h = r.bottom - r.top;
    MemDC mem(di->hDC, w, h);
    HDC dc = mem.dc;
    fill(dc, {0, 0, w, h}, C::bg);
    rrect(dc, {0, 0, w, h}, S(6), C::field, C::fieldBorder);
    Gdiplus::Graphics g(dc);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);
    Gdiplus::GraphicsPath clip;
    round_path(clip, 1, 1, (float)w - 2, (float)h - 2, (float)S(6) - 1);
    g.SetClip(&clip);
    if (ui.marquee) {
        int seg = w / 3, span = w + seg;
        int x = (ui.phase * S(5)) % span - seg;
        Gdiplus::LinearGradientBrush lb(Gdiplus::PointF((float)x, 0), Gdiplus::PointF((float)(x + seg), 0), GC(C::accent, 0), GC(C::accent, 200));
        g.FillRectangle(&lb, (float)x, 0.0f, (float)seg, (float)h);
    } else if (ui.bar_pos > 0) {
        float fw = (float)w * ui.bar_pos / 1000.0f;
        COLORREF a = ui.bar_color == C::accent ? C::accentLo : ui.bar_color;
        COLORREF b2 = ui.bar_color == C::accent ? C::accentHi : ui.bar_color;
        BYTE alpha = ui.bar_color == C::accent ? 255 : 110;
        Gdiplus::LinearGradientBrush lb(Gdiplus::PointF(0, 0), Gdiplus::PointF(fw + 1, 0), GC(a, alpha), GC(b2, alpha));
        g.FillRectangle(&lb, 0.0f, 0.0f, fw, (float)h);
    }
    g.ResetClip();
    std::wstring t = ui.status;
    if (g_busy && !ui.marquee && ui.bar_pos > 0 && ui.bar_pos < 1000) t += F(L"   %d %%", ui.bar_pos / 10);
    draw_text(dc, t, {S(10), 0, w - S(10), h}, ui.semi, ui.status_color, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

struct ScrollState {
    HWND edit = nullptr;
    int total = 1, first = 0, visible = 1;
    bool hot = false, drag = false;
    int grab = 0;
};
static std::map<HWND, ScrollState> g_sbs;

static int edit_line_height(HWND e) {
    HDC dc = GetDC(e);
    HGDIOBJ o = SelectObject(dc, (HFONT)SendMessageW(e, WM_GETFONT, 0, 0));
    TEXTMETRICW tm{};
    GetTextMetricsW(dc, &tm);
    SelectObject(dc, o);
    ReleaseDC(e, dc);
    return std::max(1, (int)tm.tmHeight);
}

static bool sb_update(HWND sb) {
    auto it = g_sbs.find(sb);
    if (it == g_sbs.end() || !it->second.edit) return false;
    auto& st = it->second;
    RECT r;
    GetClientRect(st.edit, &r);
    int total = std::max(1, (int)SendMessageW(st.edit, EM_GETLINECOUNT, 0, 0));
    int first = (int)SendMessageW(st.edit, EM_GETFIRSTVISIBLELINE, 0, 0);
    int visible = std::max(1, (int)(r.bottom - r.top) / edit_line_height(st.edit));
    bool changed = total != st.total || first != st.first || visible != st.visible;
    st.total = total;
    st.first = first;
    st.visible = visible;
    if (changed) InvalidateRect(sb, nullptr, FALSE);
    return changed;
}

static bool sb_update() { return ui.scroll ? sb_update(ui.scroll) : false; }

static bool sb_thumb(HWND sb, RECT& t) {
    auto& st = g_sbs[sb];
    RECT r;
    GetClientRect(sb, &r);
    int h = r.bottom - r.top;
    if (st.total <= st.visible || h <= 0) return false;
    int th = std::max(S(28), h * st.visible / st.total);
    int range = std::max(1, st.total - st.visible);
    int y = (h - th) * std::min(st.first, range) / range;
    t = {0, y, r.right, y + th};
    return true;
}

static void sb_scroll_to(HWND sb, int line) {
    auto& st = g_sbs[sb];
    int range = std::max(0, st.total - st.visible);
    line = std::max(0, std::min(range, line));
    int first = (int)SendMessageW(st.edit, EM_GETFIRSTVISIBLELINE, 0, 0);
    if (line != first) SendMessageW(st.edit, EM_LINESCROLL, 0, line - first);
    sb_update(sb);
}

static LRESULT CALLBACK ScrollProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    auto& st = g_sbs[h];
    switch (m) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(h, &ps);
        RECT rc;
        GetClientRect(h, &rc);
        {
            MemDC mem(hdc, rc.right, rc.bottom);
            fill(mem.dc, rc, C::field);
            RECT t;
            if (sb_thumb(h, t)) {
                bool big = st.hot || st.drag;
                int w = big ? S(6) : S(4);
                RECT p{rc.right - S(3) - w, t.top + S(2), rc.right - S(3), t.bottom - S(2)};
                rrect(mem.dc, p, w / 2, st.drag ? RGB(120, 130, 150) : big ? RGB(92, 100, 118) : RGB(58, 64, 78), CLR_NONE);
            }
        }
        EndPaint(h, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_MOUSEMOVE: {
        if (!st.hot) {
            st.hot = true;
            TRACKMOUSEEVENT t{sizeof t, TME_LEAVE, h, 0};
            TrackMouseEvent(&t);
            InvalidateRect(h, nullptr, FALSE);
        }
        if (st.drag) {
            RECT rc, t;
            GetClientRect(h, &rc);
            if (sb_thumb(h, t)) {
                int th = t.bottom - t.top, track = std::max(1, (int)rc.bottom - th);
                int y = GET_Y_LPARAM(lp) - st.grab;
                sb_scroll_to(h, (int)((long long)y * (st.total - st.visible) / track));
            }
        }
        return 0;
    }
    case WM_MOUSELEAVE:
        st.hot = false;
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    case WM_LBUTTONDOWN:
    case WM_LBUTTONDBLCLK: {
        RECT t;
        if (!sb_thumb(h, t)) return 0;
        int y = GET_Y_LPARAM(lp);
        if (y >= t.top && y < t.bottom) {
            st.drag = true;
            st.grab = y - t.top;
            SetCapture(h);
        } else sb_scroll_to(h, st.first + (y < t.top ? -st.visible : st.visible));
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    }
    case WM_LBUTTONUP:
    case WM_CAPTURECHANGED:
        if (st.drag) {
            st.drag = false;
            if (m == WM_LBUTTONUP) ReleaseCapture();
            InvalidateRect(h, nullptr, FALSE);
        }
        return 0;
    case WM_MOUSEWHEEL:
        return st.edit ? SendMessageW(st.edit, m, wp, lp) : 0;
    }
    return DefWindowProcW(h, m, wp, lp);
}

static LRESULT CALLBACK LogProc(HWND h, UINT m, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR ref) {
    LRESULT r = DefSubclassProc(h, m, wp, lp);
    switch (m) {
    case WM_MOUSEWHEEL: case WM_KEYDOWN: case WM_VSCROLL: case WM_SIZE: case WM_MOUSEMOVE: case WM_LBUTTONDOWN:
    case EM_REPLACESEL: case EM_SCROLLCARET: case EM_LINESCROLL: case WM_SETTEXT: case WM_SETFONT: case EM_SETSEL:
        sb_update((HWND)ref);
        break;
    }
    return r;
}

static void register_scroll_class() {
    static bool done = false;
    if (done) return;
    done = true;
    WNDCLASSW sc{};
    sc.lpfnWndProc = ScrollProc;
    sc.hInstance = GetModuleHandleW(nullptr);
    sc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    sc.style = CS_DBLCLKS;
    sc.lpszClassName = L"PSDScrollBar";
    RegisterClassW(&sc);
}

static HWND attach_scroll(HWND parent, HWND edit, int id) {
    register_scroll_class();
    HWND sb = CreateWindowExW(0, L"PSDScrollBar", L"", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, parent, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
    g_sbs[sb].edit = edit;
    SetWindowSubclass(edit, LogProc, 3, (DWORD_PTR)sb);
    return sb;
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
        if (IsWindowEnabled(h) && g_btn[h].kind != BK_CAP && g_btn[h].kind != BK_CAPCLOSE) {
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

static HWND mkbtn(const wchar_t* text, int id, int kind, wchar_t icon, bool tab = true) {
    HWND h = mk(WC_BUTTONW, text, BS_OWNERDRAW | (tab ? WS_TABSTOP : 0), id);
    g_btn[h] = BtnInfo{kind, icon, false, false};
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
    ui.bmin = mkbtn(L"", IDC_MIN, BK_CAP, 0xE921, false);
    ui.bmax = mkbtn(L"", IDC_MAX, BK_CAP, 0xE922, false);
    ui.bclose = mkbtn(L"", IDC_CLOSE, BK_CAPCLOSE, 0xE8BB, false);
    ui.drives = mk(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS | WS_TABSTOP | WS_VSCROLL, IDC_DRIVES);
    ui.refresh = mkbtn(L"", IDC_REFRESH, BK_ICON, 0xE72C);
    ui.driveinfo = mk(WC_STATICW, L"", SS_OWNERDRAW, IDC_DRIVEINFO);
    ui.version = mk(WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS | WS_TABSTOP | WS_VSCROLL, IDC_VERSION);
    ui.archives = mkbtn(L"", IDC_ARCHIVES, BK_ICON, 0xE895);
    ui.site = mkbtn(L"", IDC_SITE, BK_ICON, 0xE774);
    ui.file = mkbtn(L"", IDC_FILE, BK_FIELD, 0xE896);
    ui.select = mkbtn(L"Sélection", IDC_SELECT, BK_GHOST, 0xE838);
    ui.sha = mk(WC_STATICW, L"", SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS | SS_NOTIFY, IDC_SHA);
    ui.progress = mk(WC_STATICW, L"", SS_OWNERDRAW, IDC_PROGRESS);
    ui.detail = mk(WC_STATICW, L"", SS_CENTER | SS_NOPREFIX | SS_ENDELLIPSIS, IDC_DETAIL);
    ui.logbtn = mkbtn(L"", IDC_LOGBTN, BK_ICON, 0xE81C);
    ui.cache = mkbtn(L"", IDC_CACHE, BK_ICON, 0xE8B7);
    ui.format = mkbtn(L"", IDC_FORMAT, BK_DANGER, 0xE74D);
    ui.eject = mkbtn(L"", IDC_EJECT, BK_ICON, 0xE898);
    ui.devbtn = mkbtn(L"", IDC_DEV, BK_ICON, 0xEC7A);
    ui.start = mkbtn(L"Préparer", IDC_START, BK_PRIMARY, 0xE88E);
    ui.cancel = mkbtn(L"Annuler", IDC_CANCEL, BK_GHOST, 0);
    ui.log = mk(WC_EDITW, L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, IDC_LOG);
    SendMessageW(ui.log, EM_SETLIMITTEXT, 2 * 1024 * 1024, 0);
    ui.scroll = attach_scroll(g_hwnd, ui.log, IDC_SCROLL);
    for (HWND cb : {ui.drives, ui.version}) {
        dark(cb, L"DarkMode_CFD");
        SetWindowSubclass(cb, ComboProc, 2, 0);
        COMBOBOXINFO ci{sizeof ci};
        if (GetComboBoxInfo(cb, &ci) && ci.hwndList) dark(ci.hwndList, L"DarkMode_Explorer");
    }
    ui.tip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX, 0, 0, 0, 0, g_hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
    dark(ui.tip, L"DarkMode_Explorer");
    add_tip(ui.refresh, L"Rechercher les clés USB (F5)");
    add_tip(ui.archives, L"Actualiser le catalogue des firmwares");
    add_tip(ui.site, L"Ouvrir l'archive Darthsternie");
    add_tip(ui.file, L"Choisir un .PUP (Ctrl+O, ou glisse-le dans la fenêtre)");
    add_tip(ui.logbtn, L"Afficher / masquer le journal (Ctrl+L)");
    add_tip(ui.cache, L"Ouvrir le dossier de cache");
    add_tip(ui.format, L"Formater la clé en exFAT (efface tout)");
    add_tip(ui.eject, L"Éjecter la clé en toute sécurité");
    add_tip(ui.devbtn, L"Outils développeur (Ctrl+Maj+D)");
    add_tip(ui.sha, L"Cliquer pour copier");
    add_tip(ui.bmin, L"Réduire");
    add_tip(ui.bmax, L"Agrandir");
    add_tip(ui.bclose, L"Fermer");
}

static void apply_shape() {
    if (ui.win11) return;
    RECT r;
    GetWindowRect(g_hwnd, &r);
    if (IsZoomed(g_hwnd)) SetWindowRgn(g_hwnd, nullptr, TRUE);
    else SetWindowRgn(g_hwnd, CreateRoundRectRgn(0, 0, r.right - r.left + 1, r.bottom - r.top + 1, S(16), S(16)), TRUE);
}

static void apply_dpi(UINT dpi) {
    ui.dpi = dpi;
    make_fonts();
    layout();
}

static void toggle_log() {
    ui.log_visible = !ui.log_visible;
    if (!IsZoomed(g_hwnd)) {
        RECT r;
        GetWindowRect(g_hwnd, &r);
        int target = content_height(ui.log_visible);
        RECT c;
        GetClientRect(g_hwnd, &c);
        int delta = target - c.bottom;
        if (!ui.log_visible || delta > 0) SetWindowPos(g_hwnd, nullptr, 0, 0, r.right - r.left, r.bottom - r.top + delta, SWP_NOMOVE | SWP_NOZORDER);
    }
    layout();
    if (ui.log_visible) SendMessageW(ui.log, EM_SCROLLCARET, 0, 0);
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


enum { JOB_DEV = 20 };
enum {
    IDD_CLOSE = 300, IDD_SIMDL, IDD_SIMERR, IDD_CRASH_CPP, IDD_CRASH_AV, IDD_CRASH_SO, IDD_NET, IDD_BENCH, IDD_SYSINFO,
    IDD_EXPORT, IDD_CRASHDIR, IDD_LASTCRASH, IDD_CLEARCACHE, IDD_DOWNLOADS, IDD_LOG, IDD_SCROLL, IDD_CLEARLOG
};

struct Dev {
    HWND wnd = nullptr, log = nullptr, scroll = nullptr, close = nullptr;
    std::vector<std::pair<HWND, int>> grid;
    std::vector<Label> labels;
    RECT logField{};
    int captionH = 0;
} dev;


static std::wstring known_folder(REFKNOWNFOLDERID id) {
    PWSTR p = nullptr;
    std::wstring r;
    if (SUCCEEDED(SHGetKnownFolderPath(id, 0, nullptr, &p))) r = p;
    if (p) CoTaskMemFree(p);
    return r;
}

static std::wstring crash_dir() { return g_cache + L"\\crash"; }

static const wchar_t* exception_name(DWORD c) {
    switch (c) {
    case EXCEPTION_ACCESS_VIOLATION: return L"violation d'accès";
    case EXCEPTION_STACK_OVERFLOW: return L"débordement de pile";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return L"division par zéro";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return L"instruction illégale";
    case EXCEPTION_IN_PAGE_ERROR: return L"erreur de page";
    case EXCEPTION_BREAKPOINT: return L"point d'arrêt";
    case 0xC0000409: return L"fail-fast / pile corrompue";
    default: return L"exception système";
    }
}

static std::wstring os_version() {
    using RtlFn = LONG(WINAPI*)(OSVERSIONINFOW*);
    OSVERSIONINFOW v{sizeof v};
    if (auto f = (RtlFn)(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion")) f(&v);
    return F(L"Windows %lu.%lu build %lu%ls", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber, v.dwBuildNumber >= 22000 ? L" (Windows 11)" : L"");
}

struct CrashCtx {
    EXCEPTION_POINTERS* ep;
    std::wstring reason;
    DWORD tid;
};

static DWORD WINAPI crash_writer(LPVOID p) {
    auto* c = (CrashCtx*)p;
    make_dirs(crash_dir());
    SYSTEMTIME t;
    GetLocalTime(&t);
    std::wstring base = crash_dir() + F(L"\\crash_%04d%02d%02d_%02d%02d%02d", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    std::wstring txt = std::wstring(L"PSD ") + APP_VER + L" — rapport de crash\r\n";
    txt += F(L"Date    : %04d-%02d-%02d %02d:%02d:%02d\r\n", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    txt += L"Cause   : " + c->reason + L"\r\n";
    txt += F(L"Thread  : %lu\r\n", c->tid);
    txt += L"Système : " + os_version() + L"\r\n";
    if (c->ep && c->ep->ExceptionRecord) {
        auto* er = c->ep->ExceptionRecord;
        txt += F(L"Code    : 0x%08lX (%ls)\r\n", er->ExceptionCode, exception_name(er->ExceptionCode));
        txt += F(L"Adresse : 0x%p\r\n", er->ExceptionAddress);
        HMODULE mod = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)er->ExceptionAddress, &mod)) {
            wchar_t name[MAX_PATH]{};
            GetModuleFileNameW(mod, name, MAX_PATH);
            txt += F(L"Module  : %ls +0x%llX\r\n", name, (unsigned long long)((BYTE*)er->ExceptionAddress - (BYTE*)mod));
        }
        if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
            txt += F(L"Accès   : %ls à 0x%llX\r\n", er->ExceptionInformation[0] == 1 ? L"écriture" : er->ExceptionInformation[0] == 8 ? L"exécution" : L"lecture",
                     (unsigned long long)er->ExceptionInformation[1]);
    }
    txt += L"\r\n--- Journal ---\r\n" + g_log_mirror;
    std::string u = "\xEF\xBB\xBF" + U(txt);
    {
        Handle f(CreateFileW((base + L".txt").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr));
        DWORD wr = 0;
        if (f.ok()) WriteFile(f.h, u.data(), (DWORD)u.size(), &wr, nullptr);
    }
    if (HMODULE dbg = LoadLibraryExW(L"dbghelp.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) {
        using DumpFn = BOOL(WINAPI*)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);
        if (auto dump = (DumpFn)(void*)GetProcAddress(dbg, "MiniDumpWriteDump")) {
            Handle f(CreateFileW((base + L".dmp").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr));
            if (f.ok()) {
                MINIDUMP_EXCEPTION_INFORMATION mei{c->tid, c->ep, FALSE};
                dump(GetCurrentProcess(), GetCurrentProcessId(), f.h, (MINIDUMP_TYPE)(MiniDumpNormal | MiniDumpWithThreadInfo | MiniDumpWithIndirectlyReferencedMemory),
                     c->ep ? &mei : nullptr, nullptr, nullptr);
            }
        }
    }
    std::wstring msg = L"PSD a planté : " + c->reason + L".\n\nRapport et minidump enregistrés :\n" + base + L".txt";
    MessageBoxW(nullptr, msg.c_str(), L"PSD — crash", MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND);
    return 0;
}

static void write_crash(EXCEPTION_POINTERS* ep, const std::wstring& reason) {
    static std::atomic<bool> once{false};
    if (once.exchange(true)) return;
    CrashCtx c{ep, reason, GetCurrentThreadId()};
    HANDLE th = CreateThread(nullptr, 512 * 1024, crash_writer, &c, 0, nullptr);
    if (th) {
        WaitForSingleObject(th, INFINITE);
        CloseHandle(th);
    }
}

static LONG WINAPI seh_filter(EXCEPTION_POINTERS* ep) {
    DWORD code = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0;
    write_crash(ep, exception_name(code));
    TerminateProcess(GetCurrentProcess(), code ? code : 1);
    return EXCEPTION_EXECUTE_HANDLER;
}

static LONG WINAPI veh_stack(EXCEPTION_POINTERS* ep) {
    if (ep && ep->ExceptionRecord && ep->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW) {
        write_crash(ep, exception_name(EXCEPTION_STACK_OVERFLOW));
        TerminateProcess(GetCurrentProcess(), EXCEPTION_STACK_OVERFLOW);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void terminate_handler() {
    std::wstring r = L"exception C++ non capturée";
    try {
        if (auto e = std::current_exception()) std::rethrow_exception(e);
    } catch (std::exception& x) {
        r += L" (" + W(x.what()) + L")";
    } catch (...) {
    }
    write_crash(nullptr, r);
    TerminateProcess(GetCurrentProcess(), 3);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winfinite-recursion"
__attribute__((noinline)) static int recurse(int n) {
    volatile char buf[2048];
    buf[n % 2048] = (char)n;
    return recurse(n + 1) + buf[0];
}
#pragma GCC diagnostic pop

static void dev_log(const std::wstring& s) { log_line(L"[dev] " + s); }

static void trigger_crash(int kind) {
    const wchar_t* names[] = {L"exception C++ non capturée", L"violation d'accès (écriture à 0x0)", L"débordement de pile (récursion infinie)"};
    if (MessageBoxW(dev.wnd, (std::wstring(L"Déclencher un crash volontaire : ") + names[kind] + L" ?\n\nPSD va se fermer et écrire un rapport + minidump dans :\n" + crash_dir()).c_str(),
                    L"Crash volontaire", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) != IDYES)
        return;
    dev_log(std::wstring(L"Crash volontaire demandé : ") + names[kind]);
    std::thread([kind] {
        Sleep(150);
        if (kind == 0) throw std::runtime_error("crash volontaire depuis le panneau dev");
        if (kind == 1) {
            volatile int* p = nullptr;
            *p = 0x5053;
        }
        if (kind == 2) {
            ULONG g = 64 * 1024;
            SetThreadStackGuarantee(&g);
            recurse(0);
        }
    }).detach();
}

static void xorshift_fill(BYTE* p, size_t n, uint64_t& st) {
    uint64_t* q = (uint64_t*)p;
    for (size_t i = 0; i < n / 8; i++) {
        st ^= st << 13;
        st ^= st >> 7;
        st ^= st << 17;
        q[i] = st;
    }
}

static std::wstring sim_download() {
    std::wstring dl = known_folder(FOLDERID_Downloads);
    if (dl.empty()) fail(L"Dossier Téléchargements introuvable");
    SYSTEMTIME t;
    GetLocalTime(&t);
    std::wstring fin = dl + F(L"\\PSD_simulation_%02d%02d%02d.bin", t.wHour, t.wMinute, t.wSecond), part = fin + L".part";
    const uint64_t total = 256 * MiB;
    post_log(L"[dev] Téléchargement simulé → " + fin);
    Handle out(CreateFileW(part.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!out.ok()) fail(L"Écriture impossible : " + win_error(GetLastError()));
    struct Guard {
        std::wstring p;
        bool armed = true;
        ~Guard() { if (armed) DeleteFileW(p.c_str()); }
    } guard{part};
    AlignedBuf buf(MiB);
    uint64_t st = 0x9E3779B97F4A7C15ull ^ GetTickCount64(), n = 0;
    Meter m(L"Téléchargement simulé", total);
    bool dropped = false;
    while (n < total) {
        check_cancel();
        if (!dropped && n >= total * 2 / 5) {
            dropped = true;
            post_log(F(L"[dev] Tentative 1/8 : coupure réseau simulée à %ls", human(n).c_str()));
            post_prog(L"Reconnexion…", 0, 0, L"Coupure simulée, reprise HTTP Range dans 2 s");
            sleep_cancellable(2);
            post_log(F(L"[dev] Reprise HTTP Range : bytes=%llu-", (unsigned long long)n));
        }
        xorshift_fill(buf.p, MiB, st);
        if (n == 0) memcpy(buf.p, "SLB2", 4);
        DWORD wr = 0;
        if (!WriteFile(out.h, buf.p, (DWORD)MiB, &wr, nullptr) || wr != MiB) fail(L"Écriture : " + win_error(GetLastError()));
        n += MiB;
        m.tick(n);
        double speed = 25.0 + 35.0 * (0.5 + 0.5 * std::sin((double)n / (16.0 * MiB)));
        Sleep((DWORD)(1000.0 / speed));
    }
    m.tick(n, true);
    FlushFileBuffers(out.h);
    out.close();
    if (!MoveFileExW(part.c_str(), fin.c_str(), MOVEFILE_REPLACE_EXISTING)) fail(L"Renommage : " + win_error(GetLastError()));
    guard.armed = false;
    std::string sha = hash_file(fin, false, L"SHA-256 du fichier simulé");
    post_log(L"[dev] SHA-256 : " + W(sha));
    return L"Téléchargement simulé terminé : " + fin.substr(fin.find_last_of(L'\\') + 1);
}

static std::wstring sim_error() {
    post_prog(L"Opération simulée…", 0, 0, L"Échec prévu dans 2 secondes");
    post_log(L"[dev] Opération simulée lancée");
    sleep_cancellable(2);
    fail(L"Erreur simulée : le serveur a répondu HTTP 503 Service Unavailable.\n(Test de la gestion d'erreur, rien n'a été modifié.)");
}

static std::wstring net_test() {
    std::vector<std::pair<const wchar_t*, std::wstring>> urls = {
        {L"Darthsternie", D_ARCHIVE}, {L"Midnight Channel", M_ARCHIVE}, {L"PUP 13.60 (HTTPS)", builtin_catalog()[L"13.60.00"].direct}};
    int ok = 0;
    for (size_t i = 0; i < urls.size(); i++) {
        check_cancel();
        post_prog(L"Test réseau", i, urls.size(), urls[i].first);
        ULONGLONG t0 = GetTickCount64();
        try {
            Req q;
            http_open(q, urls[i].second, L"");
            ULONGLONG dt = GetTickCount64() - t0;
            std::wstring len = q.header(WINHTTP_QUERY_CONTENT_LENGTH), type = q.header(WINHTTP_QUERY_CONTENT_TYPE);
            post_log(F(L"[dev] %ls : HTTP %lu en %llu ms%ls%ls", urls[i].first, q.status, (unsigned long long)dt, type.empty() ? L"" : (L" · " + type).c_str(),
                       len.empty() ? L"" : (L" · " + human(_wcstoui64(len.c_str(), nullptr, 10))).c_str()));
            if (q.status < 400) ok++;
        } catch (AppError& e) {
            post_log(F(L"[dev] %ls : échec en %llu ms — ", urls[i].first, (unsigned long long)(GetTickCount64() - t0)) + e.msg);
        }
    }
    return F(L"Test réseau : %d/%d serveur(s) joignable(s)", ok, (int)urls.size());
}

static std::wstring bench() {
    const DWORD chunk = 8 * 1024 * 1024;
    const int rounds = 64;
    AlignedBuf buf(chunk);
    uint64_t st = 0x1234567ull;
    xorshift_fill(buf.p, chunk, st);
    auto run = [&](LPCWSTR alg, const wchar_t* name) {
        Hasher h(alg);
        Meter m(std::wstring(L"Benchmark ") + name, (uint64_t)chunk * rounds);
        LARGE_INTEGER f, a, b;
        QueryPerformanceFrequency(&f);
        QueryPerformanceCounter(&a);
        for (int i = 0; i < rounds; i++) {
            check_cancel();
            h.update(buf.p, chunk);
            m.tick((uint64_t)chunk * (i + 1));
        }
        h.hex();
        QueryPerformanceCounter(&b);
        double s = (double)(b.QuadPart - a.QuadPart) / f.QuadPart;
        double mbs = (double)chunk * rounds / MiB / s;
        post_log(F(L"[dev] %ls : %.0f Mio/s (512 Mio en %.2f s)", name, mbs, s));
        return mbs;
    };
    double a = run(BCRYPT_SHA256_ALGORITHM, L"SHA-256");
    run(BCRYPT_MD5_ALGORITHM, L"MD5");
    return F(L"Benchmark : SHA-256 à %.0f Mio/s · un PUP de 1.16 Gio se vérifie en ~%.1f s", a, 1190.0 / a);
}

static uint64_t dir_size(const std::wstring& dir) {
    uint64_t total = 0;
    WIN32_FIND_DATAW fd;
    HANDLE f = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (f == INVALID_HANDLE_VALUE) return 0;
    do {
        std::wstring n = fd.cFileName;
        if (n == L"." || n == L"..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) total += dir_size(dir + L"\\" + n);
        else total += ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
    } while (FindNextFileW(f, &fd));
    FindClose(f);
    return total;
}

static void sys_info() {
    dev_log(L"Système : " + os_version() + (ui.win11 ? L" · coins DWM" : L" · coins par région"));
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    MEMORYSTATUSEX ms{sizeof ms};
    GlobalMemoryStatusEx(&ms);
    dev_log(F(L"Processeurs : %lu · RAM : %ls (libre %ls)", si.dwNumberOfProcessors, human(ms.ullTotalPhys).c_str(), human(ms.ullAvailPhys).c_str()));
    dev_log(F(L"DPI : %u (%d %%) · police : %ls · icônes : %ls · mono : %ls", ui.dpi, ui.dpi * 100 / 96, ui.uiFont.c_str(), ui.iconFont.c_str(), ui.monoFont.c_str()));
    ULARGE_INTEGER fa{};
    GetDiskFreeSpaceExW(g_cache.substr(0, 3).c_str(), &fa, nullptr, nullptr);
    dev_log(L"Cache : " + g_cache + L" · " + human(dir_size(g_cache)) + L" · disque libre " + human(fa.QuadPart));
    std::wstring mega = megacmd();
    dev_log(L"MEGAcmd : " + (mega.empty() ? std::wstring(L"absent") : mega));
    dev_log(F(L"Catalogue : %d version(s) · clés USB : %d · exe : ", (int)g_catalog.size(), (int)g_drives.size()) + g_exe_dir);
}

static void export_log() {
    SYSTEMTIME t;
    GetLocalTime(&t);
    wchar_t file[MAX_PATH * 2]{};
    wcscpy(file, F(L"PSD_journal_%04d%02d%02d_%02d%02d.txt", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute).c_str());
    std::wstring docs = known_folder(FOLDERID_Documents);
    OPENFILENAMEW of{};
    of.lStructSize = sizeof of;
    of.hwndOwner = dev.wnd;
    of.lpstrFilter = L"Texte (*.txt)\0*.txt\0";
    of.lpstrFile = file;
    of.nMaxFile = MAX_PATH * 2;
    of.lpstrInitialDir = docs.c_str();
    of.lpstrDefExt = L"txt";
    of.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&of)) return;
    std::string u = "\xEF\xBB\xBF" + U(g_log_mirror);
    Handle f(CreateFileW(file, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr));
    DWORD wr = 0;
    if (f.ok() && WriteFile(f.h, u.data(), (DWORD)u.size(), &wr, nullptr)) dev_log(std::wstring(L"Journal exporté : ") + file);
    else dev_log(L"Export impossible : " + win_error(GetLastError()));
}

static std::wstring last_crash_report() {
    WIN32_FIND_DATAW fd;
    HANDLE f = FindFirstFileW((crash_dir() + L"\\crash_*.txt").c_str(), &fd);
    if (f == INVALID_HANDLE_VALUE) return {};
    std::wstring best;
    do {
        if (best.empty() || wcscmp(fd.cFileName, best.c_str()) > 0) best = fd.cFileName;
    } while (FindNextFileW(f, &fd));
    FindClose(f);
    return best.empty() ? best : crash_dir() + L"\\" + best;
}

static void clear_cache() {
    if (g_busy) { MessageBoxW(dev.wnd, L"Une opération est en cours.", APP_NAME, MB_ICONWARNING); return; }
    uint64_t before = dir_size(g_cache);
    if (MessageBoxW(dev.wnd, (L"Supprimer les firmwares en cache (" + human(before) + L") ?\nLes rapports de crash sont conservés.").c_str(), L"Vider le cache", MB_ICONQUESTION | MB_YESNO) != IDYES) return;
    WIN32_FIND_DATAW fd;
    HANDLE f = FindFirstFileW((g_cache + L"\\*").c_str(), &fd);
    if (f != INVALID_HANDLE_VALUE) {
        do {
            std::wstring n = fd.cFileName;
            if (n == L"." || n == L".." || n == L"crash") continue;
            std::wstring p = g_cache + L"\\" + n;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) delete_tree(p);
            else DeleteFileW(p.c_str());
        } while (FindNextFileW(f, &fd));
        FindClose(f);
    }
    dev_log(L"Cache vidé : " + human(before - std::min(before, dir_size(g_cache))) + L" libérés");
    fill_versions();
}

static void dev_layout() {
    if (!dev.log || dev.grid.size() < 14) return;
    RECT rc;
    GetClientRect(dev.wnd, &rc);
    int W = rc.right, m = S(16), cw = W - 2 * m, gap = S(8), bh = S(32);
    dev.captionH = S(40);
    dev.labels.clear();
    MoveWindow(dev.close, W - S(46), 0, S(46), S(32), FALSE);
    int y = dev.captionH + S(10);
    size_t gi = 0;
    auto section = [&](const wchar_t* t) {
        dev.labels.push_back({{m, y, m + cw, y + S(22)}, t, true});
        y += S(30);
    };
    auto row = [&](int cols) {
        int w = (cw - gap * (cols - 1)) / cols;
        for (int c = 0; c < cols && gi < dev.grid.size(); c++, gi++) MoveWindow(dev.grid[gi].first, m + c * (w + gap), y, w, bh, FALSE);
        y += bh + gap;
    };
    section(L"Simulation");
    row(2);
    y += S(6);
    section(L"Crash volontaire");
    row(3);
    dev.labels.push_back({{m, y - S(4), m + cw, y + S(12)}, L"Rapport texte + minidump écrits dans le dossier des crashs", false});
    y += S(20);
    section(L"Diagnostic");
    row(2);
    row(2);
    y += S(6);
    section(L"Fichiers");
    row(2);
    row(2);
    y += S(6);
    section(L"Console");
    MoveWindow(dev.grid[gi].first, m + cw - S(90), y - S(30) - S(4), S(90), S(26), FALSE);
    dev.logField = {m, y, m + cw, std::max(y + S(80), (int)rc.bottom - m)};
    int lw = dev.logField.right - dev.logField.left, lh = dev.logField.bottom - dev.logField.top;
    MoveWindow(dev.log, dev.logField.left + S(10), dev.logField.top + S(8), lw - S(28), lh - S(14), FALSE);
    MoveWindow(dev.scroll, dev.logField.right - S(14), dev.logField.top + S(4), S(12), lh - S(8), FALSE);
    RedrawWindow(dev.wnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN);
    sb_update(dev.scroll);
}

static void dev_paint(HDC hdc) {
    RECT rc;
    GetClientRect(dev.wnd, &rc);
    MemDC mem(hdc, rc.right, rc.bottom);
    HDC dc = mem.dc;
    fill(dc, rc, C::bg);
    fill(dc, {0, 0, rc.right, dev.captionH}, C::caption);
    fill(dc, {0, dev.captionH - 1, rc.right, dev.captionH}, C::border);
    icon(dc, 0xEC7A, {S(14), 0, S(36), dev.captionH}, C::section, S(18));
    draw_text(dc, L"Outils développeur", {S(42), 0, rc.right - S(60), dev.captionH}, ui.title, C::text, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    for (auto& l : dev.labels) {
        if (l.section) {
            int w = text_width(dc, l.text, ui.semi);
            draw_text(dc, l.text, l.r, ui.semi, C::text, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            int ly = (l.r.top + l.r.bottom) / 2;
            Gdiplus::Graphics g(dc);
            Gdiplus::LinearGradientBrush lb(Gdiplus::PointF((float)l.r.left + w + S(10), 0), Gdiplus::PointF((float)l.r.right + 1, 0), GC(C::accent), GC(C::bg));
            g.FillRectangle(&lb, (float)l.r.left + w + S(10), (float)ly, (float)(l.r.right - l.r.left - w - S(10)), 1.0f);
        } else draw_text(dc, l.text, l.r, ui.small, C::faint, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS);
    }
    rrect(dc, dev.logField, S(8), C::field, C::fieldBorder);
    if (!ui.win11) rrect(dc, {0, 0, rc.right, rc.bottom}, S(8), CLR_NONE, C::border);
}

static void dev_apply_shape() {
    if (ui.win11 || !dev.wnd) return;
    RECT r;
    GetWindowRect(dev.wnd, &r);
    SetWindowRgn(dev.wnd, CreateRoundRectRgn(0, 0, r.right - r.left + 1, r.bottom - r.top + 1, S(16), S(16)), TRUE);
}

static bool dev_busy_guard() {
    if (!g_busy) return false;
    MessageBoxW(dev.wnd, L"Une opération est déjà en cours.", APP_NAME, MB_ICONWARNING);
    return true;
}

static LRESULT CALLBACK DevProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_NCCALCSIZE:
        if (wp) return 0;
        break;
    case WM_NCACTIVATE:
        return DefWindowProcW(h, msg, wp, -1);
    case WM_NCHITTEST: {
        POINT pt{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
        ScreenToClient(h, &pt);
        RECT rc;
        GetClientRect(h, &rc);
        int b = S(6);
        bool l = pt.x < b, r = pt.x >= rc.right - b, t = pt.y < b, btm = pt.y >= rc.bottom - b;
        if (btm && l) return HTBOTTOMLEFT;
        if (btm && r) return HTBOTTOMRIGHT;
        if (l) return HTLEFT;
        if (r) return HTRIGHT;
        if (btm) return HTBOTTOM;
        if (t) return HTTOP;
        if (pt.y < dev.captionH) return HTCAPTION;
        return HTCLIENT;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        dev_paint(dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_SIZE:
        dev_apply_shape();
        dev_layout();
        return 0;
    case WM_GETMINMAXINFO: {
        auto* mm = (MINMAXINFO*)lp;
        mm->ptMinTrackSize = {S(420), S(600)};
        return 0;
    }
    case WM_DRAWITEM:
        if (((DRAWITEMSTRUCT*)lp)->CtlType == ODT_BUTTON) draw_button((DRAWITEMSTRUCT*)lp);
        return TRUE;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp;
        SetBkColor(dc, C::field);
        SetTextColor(dc, RGB(165, 172, 184));
        return (LRESULT)ui.fieldBrush;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDD_CLOSE: ShowWindow(h, SW_HIDE); break;
        case IDD_SIMDL: if (!dev_busy_guard()) run_job(JOB_DEV, sim_download); break;
        case IDD_SIMERR: if (!dev_busy_guard()) run_job(JOB_DEV, sim_error); break;
        case IDD_CRASH_CPP: trigger_crash(0); break;
        case IDD_CRASH_AV: trigger_crash(1); break;
        case IDD_CRASH_SO: trigger_crash(2); break;
        case IDD_NET: if (!dev_busy_guard()) run_job(JOB_DEV, net_test); break;
        case IDD_BENCH: if (!dev_busy_guard()) run_job(JOB_DEV, bench); break;
        case IDD_SYSINFO: sys_info(); break;
        case IDD_EXPORT: export_log(); break;
        case IDD_CRASHDIR:
            make_dirs(crash_dir());
            ShellExecuteW(h, L"open", crash_dir().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            break;
        case IDD_LASTCRASH: {
            std::wstring r = last_crash_report();
            if (r.empty()) dev_log(L"Aucun rapport de crash");
            else ShellExecuteW(h, L"open", r.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            break;
        }
        case IDD_CLEARCACHE: clear_cache(); break;
        case IDD_DOWNLOADS: ShellExecuteW(h, L"open", known_folder(FOLDERID_Downloads).c_str(), nullptr, nullptr, SW_SHOWNORMAL); break;
        case IDD_CLEARLOG:
            SetWindowTextW(dev.log, L"");
            sb_update(dev.scroll);
            break;
        }
        return 0;
    case WM_CLOSE:
        ShowWindow(h, SW_HIDE);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

static HWND devbtn(const wchar_t* text, int id, int kind, wchar_t icon) {
    HWND b = CreateWindowExW(0, WC_BUTTONW, text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 0, 0, 10, 10, dev.wnd, (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
    g_btn[b] = BtnInfo{kind, icon, false, false};
    SetWindowSubclass(b, BtnProc, 1, 0);
    SendMessageW(b, WM_SETFONT, (WPARAM)ui.font, FALSE);
    return b;
}

static void open_dev() {
    if (!dev.wnd) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = DevProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hIcon = LoadIconW(wc.hInstance, MAKEINTRESOURCEW(1));
        wc.lpszClassName = L"PSDDev";
        RegisterClassW(&wc);
        dev.wnd = CreateWindowExW(WS_EX_CONTROLPARENT, L"PSDDev", L"PSD — outils développeur", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_CLIPCHILDREN, 0, 0, 10, 10,
                                  g_hwnd, nullptr, wc.hInstance, nullptr);
        BOOL on = TRUE;
        DwmSetWindowAttribute(dev.wnd, 20, &on, sizeof on);
        int corner = 2;
        DwmSetWindowAttribute(dev.wnd, 33, &corner, sizeof corner);
        COLORREF bc = C::border;
        DwmSetWindowAttribute(dev.wnd, 34, &bc, sizeof bc);
        MARGINS mg{0, 0, 0, 1};
        DwmExtendFrameIntoClientArea(dev.wnd, &mg);
        dev.close = devbtn(L"", IDD_CLOSE, BK_CAPCLOSE, 0xE8BB);
        struct B {
            const wchar_t* t;
            int id, kind;
            wchar_t ic;
        } list[] = {
            {L"Téléchargement simulé", IDD_SIMDL, BK_GHOST, 0xE896}, {L"Erreur simulée", IDD_SIMERR, BK_GHOST, 0xE7BA},
            {L"Exception C++", IDD_CRASH_CPP, BK_DANGER, 0xE943}, {L"Accès mémoire", IDD_CRASH_AV, BK_DANGER, 0xE964}, {L"Pile infinie", IDD_CRASH_SO, BK_DANGER, 0xE81E},
            {L"Tester le réseau", IDD_NET, BK_GHOST, 0xE774}, {L"Benchmark SHA-256", IDD_BENCH, BK_GHOST, 0xE9D9},
            {L"Infos système", IDD_SYSINFO, BK_GHOST, 0xE7F4}, {L"Exporter le journal", IDD_EXPORT, BK_GHOST, 0xE74E},
            {L"Dossier crashs", IDD_CRASHDIR, BK_GHOST, 0xE8B7}, {L"Dernier rapport", IDD_LASTCRASH, BK_GHOST, 0xE8A5},
            {L"Vider le cache", IDD_CLEARCACHE, BK_DANGER, 0xE74D}, {L"Téléchargements", IDD_DOWNLOADS, BK_GHOST, 0xE896},
            {L"Effacer", IDD_CLEARLOG, BK_GHOST, 0xE894},
        };
        for (auto& b : list) dev.grid.push_back({devbtn(b.t, b.id, b.kind, b.ic), b.id});
        dev.log = CreateWindowExW(0, WC_EDITW, L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0, 10, 10, dev.wnd, (HMENU)(INT_PTR)IDD_LOG, GetModuleHandleW(nullptr), nullptr);
        SendMessageW(dev.log, EM_SETLIMITTEXT, 2 * 1024 * 1024, 0);
        SendMessageW(dev.log, WM_SETFONT, (WPARAM)ui.mono, FALSE);
        dev.scroll = attach_scroll(dev.wnd, dev.log, IDD_SCROLL);
        g_dev_log = dev.log;
        std::wstring mirror = g_log_mirror;
        SetWindowTextW(dev.log, mirror.c_str());
        SendMessageW(dev.log, EM_SETSEL, mirror.size(), mirror.size());
        SendMessageW(dev.log, EM_SCROLLCARET, 0, 0);
        RECT mr;
        GetWindowRect(g_hwnd, &mr);
        int w = S(440), h = S(690);
        HMONITOR mon = MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi{sizeof mi};
        GetMonitorInfoW(mon, &mi);
        int x = mr.right + S(12);
        if (x + w > mi.rcWork.right) x = std::max((int)mi.rcWork.left, (int)mr.left - S(12) - w);
        int y = std::max((int)mi.rcWork.top, std::min((int)mr.top, (int)mi.rcWork.bottom - h));
        SetWindowPos(dev.wnd, nullptr, x, y, w, h, SWP_NOZORDER | SWP_FRAMECHANGED);
        dev_layout();
        dev_log(L"Panneau développeur ouvert");
    }
    ShowWindow(dev.wnd, SW_SHOWNORMAL);
    SetForegroundWindow(dev.wnd);
}

static const wchar_t* REG_KEY = L"Software\\PSD";

static std::wstring reg_get(const wchar_t* name) {
    wchar_t buf[512]{};
    DWORD sz = sizeof buf;
    if (RegGetValueW(HKEY_CURRENT_USER, REG_KEY, name, RRF_RT_REG_SZ, nullptr, buf, &sz) != ERROR_SUCCESS) return {};
    return buf;
}

static void reg_set(const wchar_t* name, const std::wstring& v) {
    RegSetKeyValueW(HKEY_CURRENT_USER, REG_KEY, name, REG_SZ, v.c_str(), (DWORD)((v.size() + 1) * sizeof(wchar_t)));
}

static void copy_sha() {
    const Firmware* f = selected_fw();
    if (!f || !is_hex(f->sha256, 64)) return;
    std::wstring s = W(f->sha256);
    if (!OpenClipboard(g_hwnd)) return;
    EmptyClipboard();
    HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, (s.size() + 1) * sizeof(wchar_t));
    if (g) {
        memcpy(GlobalLock(g), s.c_str(), (s.size() + 1) * sizeof(wchar_t));
        GlobalUnlock(g);
        SetClipboardData(CF_UNICODETEXT, g);
    }
    CloseClipboard();
    if (!g_busy) set_text(ui.detail, L"SHA-256 copié dans le presse-papiers");
}

static void check_previous_crash() {
    std::wstring r = last_crash_report();
    if (r.empty()) return;
    std::wstring name = r.substr(r.find_last_of(L'\\') + 1);
    if (reg_get(L"LastCrashSeen") == name) return;
    reg_set(L"LastCrashSeen", name);
    log_line(L"Le lancement précédent a planté. Rapport : " + r);
}

static bool handle_shortcut(const MSG& m) {
    if (m.message != WM_KEYDOWN) return false;
    if (m.hwnd != g_hwnd && !IsChild(g_hwnd, m.hwnd)) return false;
    bool ctrl = GetKeyState(VK_CONTROL) < 0, shift = GetKeyState(VK_SHIFT) < 0;
    if (m.wParam == VK_F5) { scan_drives(); return true; }
    if (ctrl && !shift && m.wParam == 'O') { if (!g_busy) choose_local(); return true; }
    if (ctrl && !shift && m.wParam == 'L') { SendMessageW(g_hwnd, WM_COMMAND, IDC_LOGBTN, 0); return true; }
    if (ctrl && shift && m.wParam == 'D') { open_dev(); return true; }
    return false;
}

static int frame_thickness() {
    return GetSystemMetricsForDpi(SM_CXFRAME, ui.dpi) + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, ui.dpi);
}

static LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    if (ui.tbmsg && msg == ui.tbmsg) {
        if (!ui.tb) CoCreateInstance(CLSID_TaskbarList, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskbarList3, (void**)&ui.tb);
        if (ui.tb) ui.tb->HrInit();
        return 0;
    }
    switch (msg) {
    case WM_NCCALCSIZE:
        if (wp) {
            auto* p = (NCCALCSIZE_PARAMS*)lp;
            if (IsZoomed(h)) {
                int f = frame_thickness();
                p->rgrc[0].left += f;
                p->rgrc[0].top += f;
                p->rgrc[0].right -= f;
                p->rgrc[0].bottom -= f;
            }
            return 0;
        }
        break;
    case WM_NCACTIVATE:
        return DefWindowProcW(h, msg, wp, -1);
    case WM_NCHITTEST: {
        POINT pt{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
        ScreenToClient(h, &pt);
        RECT rc;
        GetClientRect(h, &rc);
        if (!IsZoomed(h)) {
            int b = S(6);
            bool l = pt.x < b, r = pt.x >= rc.right - b, t = pt.y < b, btm = pt.y >= rc.bottom - b;
            if (t && l) return HTTOPLEFT;
            if (t && r) return HTTOPRIGHT;
            if (btm && l) return HTBOTTOMLEFT;
            if (btm && r) return HTBOTTOMRIGHT;
            if (l) return HTLEFT;
            if (r) return HTRIGHT;
            if (t) return HTTOP;
            if (btm) return HTBOTTOM;
        }
        if (pt.y < ui.captionH) return HTCAPTION;
        return HTCLIENT;
    }
    case WM_CREATE: {
        g_hwnd = h;
        ui.dpi = GetDpiForWindow(h);
        BOOL on = TRUE;
        DwmSetWindowAttribute(h, 20, &on, sizeof on);
        int corner = 2;
        ui.win11 = SUCCEEDED(DwmSetWindowAttribute(h, 33, &corner, sizeof corner));
        COLORREF bc = C::border;
        DwmSetWindowAttribute(h, 34, &bc, sizeof bc);
        MARGINS mg{0, 0, 0, 1};
        DwmExtendFrameIntoClientArea(h, &mg);
        if (font_exists(L"Segoe UI Variable Text")) ui.uiFont = L"Segoe UI Variable Text";
        if (font_exists(L"Segoe Fluent Icons")) ui.iconFont = L"Segoe Fluent Icons";
        if (font_exists(L"Cascadia Mono")) ui.monoFont = L"Cascadia Mono";
        ui.bgBrush = CreateSolidBrush(C::bg);
        ui.fieldBrush = CreateSolidBrush(C::field);
        ui.has_mega = !megacmd().empty();
        create_controls();
        apply_dpi(ui.dpi);
        if (auto v = reg_get(L"LastVersion"); !v.empty()) g_selected_version = v;
        g_catalog = builtin_catalog();
        fill_versions();
        fill_drives();
        apply_busy();
        log_line(std::wstring(APP_NAME) + L" " + APP_VER + L"  ·  cache : " + g_cache);
        log_line(L"Prépare uniquement une clé de mise à jour officielle : ne contourne aucune restriction PS5.");
        check_previous_crash();
        if (reg_get(L"LogVisible") == L"1") PostMessageW(h, WM_COMMAND, IDC_LOGBTN, 0);
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
        apply_shape();
        layout();
        InvalidateRect(ui.bmax, nullptr, FALSE);
        return 0;
    case WM_GETMINMAXINFO: {
        auto* mm = (MINMAXINFO*)lp;
        int minh = content_height(false) + (ui.log_visible ? S(90) : 0);
        mm->ptMinTrackSize = {S(480), minh};
        if (!ui.log_visible) mm->ptMaxTrackSize.y = content_height(false);
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
        if (c == ui.sha) {
            SetBkColor(dc, C::field);
            SetTextColor(dc, C::dim);
            return (LRESULT)ui.fieldBrush;
        }
        SetBkColor(dc, C::bg);
        SetTextColor(dc, C::dim);
        return (LRESULT)ui.bgBrush;
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
                    reg_set(L"LastVersion", f->version);
                    if (!g_local_version.empty() && g_local_version != f->version) {
                        g_local_path.clear();
                        g_local_version.clear();
                    }
                }
                update_fw_info();
            }
            break;
        case IDC_MIN: ShowWindow(h, SW_MINIMIZE); break;
        case IDC_MAX: ShowWindow(h, IsZoomed(h) ? SW_RESTORE : SW_MAXIMIZE); break;
        case IDC_CLOSE: PostMessageW(h, WM_CLOSE, 0, 0); break;
        case IDC_REFRESH: scan_drives(); break;
        case IDC_ARCHIVES: load_catalog(); break;
        case IDC_SITE: ShellExecuteW(h, L"open", D_ARCHIVE, nullptr, nullptr, SW_SHOWNORMAL); break;
        case IDC_FILE:
        case IDC_SELECT: if (!g_busy) choose_local(); break;
        case IDC_LOGBTN:
            toggle_log();
            reg_set(L"LogVisible", ui.log_visible ? L"1" : L"0");
            break;
        case IDC_DEV: open_dev(); break;
        case IDC_SHA:
            if (code == STN_CLICKED) copy_sha();
            break;
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
        ui.status = p->phase;
        ui.status_color = C::text;
        set_text(ui.detail, p->detail);
        set_progress(p->cur, p->total);
        redraw_bar();
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
    SetUnhandledExceptionFilter(seh_filter);
    AddVectoredExceptionHandler(1, veh_stack);
    std::set_terminate(terminate_handler);
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
    wc.lpszClassName = L"PSDWnd";
    RegisterClassExW(&wc);

    std::wstring title = std::wstring(APP_NAME) + L" " + APP_VER;
    HWND h = CreateWindowExW(WS_EX_CONTROLPARENT | WS_EX_APPWINDOW, wc.lpszClassName, title.c_str(), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 520, 700, nullptr, nullptr, inst, nullptr);
    if (!h) return 1;
    int ww = S(500), wh = content_height(false);
    HMONITOR mon = MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi{sizeof mi};
    GetMonitorInfoW(mon, &mi);
    SetWindowPos(h, nullptr, mi.rcWork.left + (mi.rcWork.right - mi.rcWork.left - ww) / 2, mi.rcWork.top + (mi.rcWork.bottom - mi.rcWork.top - wh) / 2, ww, wh, SWP_NOZORDER | SWP_FRAMECHANGED);
    ShowWindow(h, show);
    UpdateWindow(h);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0) {
        if (handle_shortcut(m)) continue;
        if (dev.wnd && IsDialogMessageW(dev.wnd, &m)) continue;
        if (IsDialogMessageW(h, &m)) continue;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    if (g_session) WinHttpCloseHandle(g_session);
    Gdiplus::GdiplusShutdown(gtoken);
    CoUninitialize();
    return 0;
}
