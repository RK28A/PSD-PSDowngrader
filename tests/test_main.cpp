#define wWinMain psd_app_main
#include "../src/main.cpp"
#undef wWinMain

#include <cstdio>

static int g_fail = 0, g_pass = 0;

static void check(bool c, const char* name) {
    printf("%s  %s\n", c ? "ok  " : "FAIL", name);
    fflush(stdout);
    (c ? g_pass : g_fail)++;
}

static bool contains(const std::wstring& s, const wchar_t* part) { return s.find(part) != std::wstring::npos; }

static std::wstring g_tmp;

static void write_file(const std::wstring& p, const std::string& data) {
    Handle h(CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr));
    DWORD wr = 0;
    WriteFile(h.h, data.data(), (DWORD)data.size(), &wr, nullptr);
}

static std::string read_file(const std::wstring& p) {
    Handle h(CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
    std::string s((size_t)file_size(p), 0);
    DWORD got = 0;
    if (!s.empty()) ReadFile(h.h, s.data(), (DWORD)s.size(), &got, nullptr);
    return s;
}

static std::string sha_of(const std::string& d) {
    Hasher h(BCRYPT_SHA256_ALGORITHM);
    h.update(d.data(), d.size());
    return h.hex();
}

static std::string fake_pup(size_t size, uint32_t seed) {
    std::string d(size, 0);
    uint64_t st = 0x9E3779B97F4A7C15ull ^ seed;
    for (size_t i = 0; i + 8 <= size; i += 8) {
        st ^= st << 13;
        st ^= st >> 7;
        st ^= st << 17;
        memcpy(&d[i], &st, 8);
    }
    memset(&d[0], 0, 0x200);
    memcpy(&d[0], "SLB2", 4);
    uint32_t v = 1, count = 2;
    memcpy(&d[4], &v, 4);
    memcpy(&d[12], &count, 4);
    for (uint32_t i = 0; i < 2; i++) {
        size_t o = 0x20 + i * 48;
        uint32_t off = 1 + i * 4096, sz = 1024 * 1024;
        memcpy(&d[o], &off, 4);
        memcpy(&d[o + 4], &sz, 4);
        std::string nm = "PS5UPDATE" + std::to_string(i + 1) + ".PUP";
        memcpy(&d[o + 16], nm.data(), nm.size());
    }
    return d;
}

static void reset_hooks() {
    g_cancel = false;
    g_device_lost = false;
    g_test_fail_after = 0;
    g_test_fail_code = 0;
    g_test_cancel_after = 0;
}

template <class Fn> static std::wstring expect_error(Fn fn, int& kind) {
    kind = 0;
    try {
        fn();
    } catch (AppError& e) {
        kind = 2;
        return e.msg;
    } catch (Cancelled& c) {
        kind = 1;
        return c.msg;
    }
    return L"";
}

static void test_parsing() {
    Catalog c = builtin_catalog();
    std::string mid = R"(<h2>System Firmware</h2><table>
<tr><td>Firmware 13.60</td><td>767a94eac034d33907a6ff57af05bc30ce057258ad1cf4b5ffb75d5e21112561</td><td><a href="/SonyPS/Firmware/download/767a94eac034d33907a6ff57af05bc30ce057258ad1cf4b5ffb75d5e21112561/X.PUP">dl</a></td></tr>
<tr><td>Firmware 14.00</td><td>ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff</td></tr>
<tr><td>Firmware 12.00</td><td>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</td><td><a href='/SonyPS/Firmware/download/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Y.PUP'>dl</a></td></tr>
</table><h3>Recovery</h3><table><tr><td>Firmware 11.00</td><td>bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb</td></tr></table>)";
    parse_midnight(mid, c);
    check(c[L"13.60.00"].refs.size() == 2, "midnight: SHA concordant ajoute une 2e source");
    check(c[L"14.00.00"].sha256 == "1eb4b18451e0f064fc23b5bd4c95cae7f6489f9ad1148b5dfb0d66452a108ebc", "midnight: SHA contradictoire ignoré");
    check(c[L"12.00.00"].direct.find(L"archive.midnightchannel.net") != std::wstring::npos, "midnight: lien HTTPS résolu");
    check(c.find(L"11.00.00") == c.end(), "midnight: section Recovery ignorée");

    Catalog c2 = builtin_catalog();
    std::string changed = R"(<div class="card"><span>Firmware 15.00</span><p>Update file</p>
<a class="btn" href="/SonyPS/Firmware/download/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/PS5UPDATE.PUP">Download</a></div>
<div><span>Firmware 9.00 recovery</span><a href="/SonyPS/Firmware/download/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/R.PUP">x</a></div>)";
    parse_midnight(changed, c2);
    check(c2[L"15.00.00"].sha256 == std::string(64, 'c') && !c2[L"15.00.00"].direct.empty(), "midnight: extraction hors tableau (mise en page changée)");
    check(c2.find(L"09.00.00") == c2.end(), "midnight: recovery ignoré hors tableau");

    Catalog c3 = builtin_catalog();
    std::string dar = R"(<h2>Official Firmwares</h2><table><tr><td>Firmware 13.60</td><td>06A74EFCE009503170B7ADD7FECFEB36</td><td><a href="https://mega.nz/file/abc#key">MEGA</a></td></tr></table>
<p>Firmware 14.10 <a href="https://mega.nz/file/zzz#kk">lien</a></p>)";
    parse_darthsternie(dar, c3);
    check(c3[L"13.60.00"].mega == L"https://mega.nz/file/abc#key", "darthsternie: lien MEGA");
    check(std::find(c3[L"13.60.00"].refs.begin(), c3[L"13.60.00"].refs.end(), L"Darthsternie (MD5)") != c3[L"13.60.00"].refs.end(), "darthsternie: MD5 concordant compté");
    check(c3[L"14.10.00"].mega == L"https://mega.nz/file/zzz#kk", "darthsternie: lien MEGA hors tableau");

    Catalog c4 = builtin_catalog();
    load_user_refs(R"({"13.60": {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"}, "16.00": {"sha256": "1111111111111111111111111111111111111111111111111111111111111111"}})", c4);
    check(c4[L"13.60.00"].sha256[0] == '7', "json: conflit refusé");
    check(c4[L"16.00.00"].sha256 == std::string(64, '1'), "json: nouvelle version ajoutée");
}

static void test_policy() {
    check(allowed_download(L"https://archive.midnightchannel.net/SonyPS/Firmware/download/x/A.PUP"), "url: miroir autorisé");
    check(!allowed_download(L"http://archive.midnightchannel.net/SonyPS/Firmware/download/x/A.PUP"), "url: HTTP refusé");
    check(!allowed_download(L"https://evil.net/SonyPS/Firmware/download/x/A.PUP"), "url: autre domaine refusé");
    check(!allowed_download(L"https://archive.midnightchannel.net/SonyPS/Firmware/download/x/A.exe"), "url: extension refusée");
    check(!host_allowed(L"https://archive.midnightchannel.net.evil.com/a", {L"archive.midnightchannel.net"}), "redirection: sous-domaine piège refusé");
    check(mega_url_ok(L"https://mega.nz/file/AbC-_1#KeY-_2"), "mega: lien valide");
    check(!mega_url_ok(L"https://mega.nz/file/abc#k\" & calc.exe"), "mega: injection refusée");
    check(quote_arg(L"C:\\a b\\") == L"\"C:\\a b\\\\\"", "quote_arg: antislash final");
    check(quote_arg(L"x\"y") == L"\"x\\\"y\"", "quote_arg: guillemet échappé");
    check(strong_etag(L"\"v1\"") && !strong_etag(L"W/\"v1\""), "etag: fort / faible");
    Drive d;
    const wchar_t* fs[] = {L"FAT32", L"exFAT", L"NTFS", L"RAW"};
    bool exp[] = {true, true, false, false};
    bool ok = true;
    for (int i = 0; i < 4; i++) {
        d.fs = fs[i];
        ok = ok && d.fs_ok() == exp[i];
    }
    check(ok, "systèmes de fichiers FAT32/exFAT/NTFS/RAW");
}

static void test_files() {
    std::wstring p = g_tmp + L"\\pup.bin";
    std::string data = fake_pup(6 * 1024 * 1024, 1);
    write_file(p, data);
    PupInfo pi = inspect_pup(p);
    check(pi.structure_ok && contains(pi.summary, L"PS5UPDATE1.PUP"), "SLB2: structure valide");
    std::string bad = data;
    uint32_t count = 999;
    memcpy(&bad[12], &count, 4);
    write_file(p, bad);
    check(!inspect_pup(p).structure_ok, "SLB2: structure invalide détectée");
    write_file(p, data);
    std::string a = hash_file(p, HM_BUFFERED, L"t"), b = hash_file(p, HM_DIRECT, L"t");
    check(a == sha_of(data) && b == a, "hash: lecture normale et directe identiques");
    write_sidecar(p, a);
    check(sidecar_ok(p, a), "cache: vérification enregistrée");
    Sleep(20);
    data[100] ^= 1;
    write_file(p, data);
    check(!sidecar_ok(p, a), "cache: fichier modifié => à revérifier");
}

static void test_copy() {
    std::wstring src = g_tmp + L"\\src.PUP", dir = g_tmp + L"\\usb";
    need_dirs(dir);
    std::string data = fake_pup(24 * 1024 * 1024, 7);
    write_file(src, data);
    Firmware fw;
    fw.version = L"99.00.00";
    fw.sha256 = sha_of(data);
    std::wstring fin = dir + L"\\PS5UPDATE.PUP", tmp = fin + L".tmp";
    int kind = 0;

    reset_hooks();
    write_file(tmp, "reste d'un crash");
    std::wstring e = expect_error([&] { copy_verify_core(src, dir, fw, {}); }, kind);
    check(kind == 0 && read_file(fin) == data && !file_exists(tmp), "copie: succès, temporaire abandonné nettoyé");

    std::string old = read_file(fin);
    Firmware wrong = fw;
    wrong.sha256[0] = wrong.sha256[0] == 'a' ? 'b' : 'a';
    e = expect_error([&] { copy_verify_core(src, dir, wrong, {}); }, kind);
    check(kind == 2 && contains(e, L"différent") && !file_exists(tmp) && read_file(fin) == old, "copie: SHA-256 incorrect refusé, ancien fichier intact");

    reset_hooks();
    g_test_cancel_after = 8 * 1024 * 1024;
    e = expect_error([&] { copy_verify_core(src, dir, fw, {}); }, kind);
    check(kind == 1 && !file_exists(tmp), "copie: annulation sans fichier temporaire");

    reset_hooks();
    g_test_fail_after = 10 * 1024 * 1024;
    g_test_fail_code = ERROR_DISK_FULL;
    e = expect_error([&] { copy_verify_core(src, dir, fw, {}); }, kind);
    check(kind == 2 && contains(e, L"espace") && !file_exists(tmp), "copie: clé pleine");

    reset_hooks();
    g_test_fail_after = 5 * 1024 * 1024;
    g_test_fail_code = ERROR_DEVICE_NOT_CONNECTED;
    e = expect_error([&] { copy_verify_core(src, dir, fw, {}); }, kind);
    check(kind == 2 && contains(e, L"retirée"), "copie: clé débranchée");

    reset_hooks();
    g_test_fail_after = 1;
    g_test_fail_code = ERROR_WRITE_PROTECT;
    e = expect_error([&] { copy_verify_core(src, dir, fw, {}); }, kind);
    check(kind == 2 && contains(e, L"protégée"), "copie: protection en écriture");

    reset_hooks();
    g_device_lost = true;
    e = expect_error([&] { copy_verify_core(src, dir, fw, {}); }, kind);
    check(kind == 2 && contains(e, L"retirée"), "copie: retrait détecté par notification");

    reset_hooks();
    std::wstring backup = g_tmp + L"\\backup.PUP";
    copy_with_meter(fin, backup, L"t", false);
    DeleteFileW(fin.c_str());
    CopyOpts o;
    o.backup = backup;
    e = expect_error([&] { copy_verify_core(src, dir, wrong, o); }, kind);
    check(kind == 2 && read_file(fin) == old && !file_exists(backup), "copie: ancien PUP restauré après échec");

    reset_hooks();
    std::wstring cache_src = g_tmp + L"\\cache.PUP";
    write_file(cache_src, data);
    o = CopyOpts{};
    o.src_is_cache = true;
    e = expect_error([&] { copy_verify_core(cache_src, dir, wrong, o); }, kind);
    check(kind == 2 && !file_exists(cache_src), "copie: cache corrompu supprimé");

    reset_hooks();
    o = CopyOpts{};
    o.recheck = [] { fail(L"La capacité de la clé a changé"); };
    e = expect_error([&] { copy_verify_core(src, dir, fw, o); }, kind);
    check(kind == 2 && contains(e, L"capacité") && !file_exists(tmp), "copie: changement d'identité avant validation");
}

static void test_http(int port) {
    g_test_prefix = F(L"https://127.0.0.1:%d/SonyPS/Firmware/download/", port);
    g_test_insecure = true;
    g_test_fast = true;
    std::wstring dir = g_tmp + L"\\dl";
    need_dirs(dir);
    auto fw_for = [&](const wchar_t* name, const std::string& sha) {
        Firmware f;
        f.version = L"99.00.00";
        f.sha256 = sha;
        f.size = 10 * 1024 * 1024;
        f.direct = g_test_prefix + W(sha) + L"/" + name;
        return f;
    };
    int kind = 0;
    reset_hooks();
    std::wstring dest = dir + L"\\a.PUP";
    std::wstring e = expect_error([&] { download_http(fw_for(L"plain.PUP", std::string(64, 'a')), dest); }, kind);
    std::string ref = read_file(dest);
    std::string ref_sha = sha_of(ref);
    check(kind == 0 && ref.size() == 10 * 1024 * 1024 && ref.compare(0, 4, "SLB2") == 0, "http: téléchargement simple");
    if (kind) printf("      %ls\n", e.c_str());

    std::wstring d2 = dir + L"\\b.PUP";
    e = expect_error([&] { download_http(fw_for(L"flaky.PUP", ref_sha), d2); }, kind);
    check(kind == 0 && sha_of(read_file(d2)) == ref_sha && !file_exists(d2 + L".part"), "http: 4 coupures, reprise HTTP Range");
    if (kind) printf("      %ls\n", e.c_str());

    std::wstring d3 = dir + L"\\c.PUP";
    e = expect_error([&] { download_http(fw_for(L"changing.PUP", ref_sha), d3); }, kind);
    check(kind == 0 && sha_of(read_file(d3)) == ref_sha, "http: ETag modifié, reprise à zéro correcte");
    if (kind) printf("      %ls\n", e.c_str());

    e = expect_error([&] { download_http(fw_for(L"redirect.PUP", ref_sha), dir + L"\\d.PUP"); }, kind);
    check(kind == 2 && contains(e, L"Redirection refusée"), "http: redirection vers un autre domaine refusée");

    e = expect_error([&] { download_http(fw_for(L"missing.PUP", ref_sha), dir + L"\\e.PUP"); }, kind);
    check(kind == 2 && contains(e, L"404"), "http: 404 fatal sans réessais");

    e = expect_error([&] { download_http(fw_for(L"html.PUP", ref_sha), dir + L"\\f.PUP"); }, kind);
    check(kind == 2 && contains(e, L"HTML"), "http: page HTML refusée");

    Firmware wrong = fw_for(L"plain.PUP", std::string(64, '0'));
    wrong.size = 0;
    std::wstring g = dir + L"\\g.PUP";
    e = expect_error([&] { download_http(wrong, g); verify_download(wrong, g, L"t"); }, kind);
    check(kind == 2 && contains(e, L"SHA-256 différent") && !file_exists(g), "http: firmware au SHA-256 incorrect supprimé");
}

int main(int argc, char** argv) {
    wchar_t t[MAX_PATH]{};
    GetTempPathW(MAX_PATH, t);
    g_tmp = std::wstring(t) + F(L"psd_tests_%lu", GetCurrentProcessId());
    need_dirs(g_tmp);
    g_cache = g_tmp + L"\\cache";
    need_dirs(g_cache);
    http_init();
    test_parsing();
    test_policy();
    test_files();
    test_copy();
    if (argc > 1) test_http(atoi(argv[1]));
    else printf("skip  tests HTTP (port du serveur non fourni)\n");
    delete_tree(g_tmp);
    printf("\n%d réussi(s), %d échec(s)\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
