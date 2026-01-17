#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <regex>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <atomic>
#include <mutex>
#include <thread>

#if defined(__unix__) || defined(__APPLE__)
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#endif

namespace fs = std::filesystem;

struct Candidate {
    size_t lineIndex{};
    std::string indent;
    std::string addr8;     // 8 hex digits
    std::string hexbytes;  // hex string (no separators)
    std::string mnemonic;  // normalized for WASM
    bool hasLocLabelRef = false;
    std::string originalLine;
};

struct Options {
    std::string inAsm;
    std::string origBin;
    std::string outAsm;
    std::string wasm = "wasm";
    std::string wlink = "wlink";
    std::string wdis = "wdis";
    int chunk = 1024;
    int jobs = 1;
    int wasmWarnLevel = -1; // -1 = tool default
    bool quiet = false;
    bool keepWorkdir = false;
};

static void die(const std::string &msg) {
    std::cerr << "ERROR: " << msg << "\n";
    std::exit(2);
}

static bool fileExists(const std::string &p) {
    std::error_code ec;
    return fs::exists(fs::path(p), ec);
}

static std::vector<std::string> readFileLines(const std::string &path) {
    std::ifstream f(path);
    if (!f) die("failed to open: " + path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        lines.push_back(line);
    }
    return lines;
}

static void writeStringToFile(const fs::path &path, const std::string &text) {
    std::ofstream f(path, std::ios::binary);
    if (!f) die("failed to write: " + path.string());
    f.write(text.data(), static_cast<std::streamsize>(text.size()));
}

static bool bytesEqualFiles(const fs::path &a, const fs::path &b) {
    std::ifstream fa(a, std::ios::binary);
    std::ifstream fb(b, std::ios::binary);
    if (!fa || !fb) return false;

    std::array<char, 1 << 16> ba{};
    std::array<char, 1 << 16> bb{};

    while (true) {
        fa.read(ba.data(), static_cast<std::streamsize>(ba.size()));
        fb.read(bb.data(), static_cast<std::streamsize>(bb.size()));
        auto ra = fa.gcount();
        auto rb = fb.gcount();
        if (ra != rb) return false;
        if (ra == 0) return true;
        if (std::memcmp(ba.data(), bb.data(), static_cast<size_t>(ra)) != 0) return false;
    }
}

static std::string normalizeHexLiteralsForWasm(std::string s) {
    // Replace occurrences of [+|-]0x[0-9a-fA-F]+ with MASM-style hex: [+|-]NNh
    // If it would start with A-F, prefix with 0.
    static const std::regex re(R"(([+-]?)(0x)([0-9A-Fa-f]+))");

    std::string out;
    out.reserve(s.size());

    std::sregex_iterator it(s.begin(), s.end(), re);
    std::sregex_iterator end;

    size_t last = 0;
    for (; it != end; ++it) {
        const auto &m = *it;
        out.append(s, last, static_cast<size_t>(m.position()) - last);

        std::string sign = m.str(1);
        std::string hex = m.str(3);
        for (auto &c : hex) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (!hex.empty() && hex[0] >= 'A' && hex[0] <= 'F') hex = "0" + hex;
        out.append(sign);
        out.append(hex);
        out.push_back('h');

        last = static_cast<size_t>(m.position() + m.length());
    }
    out.append(s, last, std::string::npos);
    return out;
}

static bool startsWith(std::string_view s, std::string_view pfx) {
    return s.size() >= pfx.size() && s.substr(0, pfx.size()) == pfx;
}

static std::string_view ltrimView(std::string_view s) {
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) i++;
    return s.substr(i);
}

static std::string_view rtrimView(std::string_view s) {
    size_t n = s.size();
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) n--;
    return s.substr(0, n);
}

static bool isHexChar(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static bool isAlpha(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static std::optional<uint32_t> parseNumberToken(std::string_view tok) {
    tok = rtrimView(ltrimView(tok));
    if (tok.empty()) return std::nullopt;

    // MASM style: 0AAh / AAh / 10h
    bool hex = false;
    if (tok.size() >= 2 && (tok[0] == '0') && (tok[1] == 'x' || tok[1] == 'X')) {
        tok = tok.substr(2);
        hex = true;
    } else if (tok.size() >= 1 && (tok.back() == 'h' || tok.back() == 'H')) {
        tok = tok.substr(0, tok.size() - 1);
        hex = true;
    }

    if (tok.empty()) return std::nullopt;

    uint32_t value = 0;
    if (hex) {
        for (char c : tok) {
            if (!isHexChar(c)) return std::nullopt;
            value *= 16;
            if (c >= '0' && c <= '9') value += static_cast<uint32_t>(c - '0');
            else {
                c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                value += static_cast<uint32_t>(10 + (c - 'A'));
            }
            if (value > 0xFFFFFFFFu) return std::nullopt;
        }
    } else {
        for (char c : tok) {
            if (c < '0' || c > '9') return std::nullopt;
            value = value * 10 + static_cast<uint32_t>(c - '0');
        }
    }

    return value;
}

static std::optional<std::string> hexBytesFromDbOperands(std::string_view line) {
    // line must start with optional indent + "db ", and may contain a trailing ';' comment.
    std::string_view v = line;
    v = ltrimView(v);
    if (!startsWith(v, "db ")) return std::nullopt;

    auto semi = v.find(';');
    std::string_view args = (semi == std::string_view::npos) ? v.substr(3) : v.substr(3, semi - 3);
    args = rtrimView(args);
    if (args.empty()) return std::nullopt;

    std::string hex;
    size_t pos = 0;
    while (pos < args.size()) {
        size_t comma = args.find(',', pos);
        std::string_view tok = (comma == std::string_view::npos) ? args.substr(pos) : args.substr(pos, comma - pos);
        tok = rtrimView(ltrimView(tok));
        if (tok.empty()) return std::nullopt;

        auto n = parseNumberToken(tok);
        if (!n.has_value() || *n > 0xFFu) return std::nullopt;

        static const char *digits = "0123456789ABCDEF";
        uint8_t b = static_cast<uint8_t>(*n);
        hex.push_back(digits[(b >> 4) & 0xF]);
        hex.push_back(digits[b & 0xF]);

        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }

    if (hex.empty()) return std::nullopt;
    return hex;
}

static std::optional<Candidate> parseDbLineCandidate(const std::string &line, size_t lineIndex) {
    // Expected format:
    // <indent>db <...> ; AAAAAAAAh HEXBYTES  <mnemonic>
    // Alternative (DOSRE mnemonic.safe.asm):
    // <indent>db <...> ; AAAAAAAAh <mnemonic>
    // We'll parse with simple scanning (no heavy regex per line).

    std::string_view v(line);
    auto vtrim = ltrimView(v);
    if (!startsWith(vtrim, "db ")) return std::nullopt;

    size_t indentLen = v.size() - vtrim.size();
    std::string indent(line.substr(0, indentLen));

    auto semi = v.find(';');
    if (semi == std::string_view::npos) return std::nullopt;

    std::string_view after = ltrimView(v.substr(semi + 1));
    after = rtrimView(after);

    // addr token: 8 hex + 'h'
    if (after.size() < 9) return std::nullopt;
    for (int i = 0; i < 8; i++) {
        if (!isHexChar(after[static_cast<size_t>(i)])) return std::nullopt;
    }
    if (after[8] != 'h' && after[8] != 'H') return std::nullopt;
    std::string addr8(after.substr(0, 8));
    for (auto &c : addr8) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    after = ltrimView(after.substr(9));
    if (after.empty()) return std::nullopt;

    std::string hexbytes;
    std::string mnemonic;

    // If a contiguous HEXBYTES token is present, use it. Otherwise derive it from the db operands.
    size_t hbLen = 0;
    while (hbLen < after.size() && isHexChar(after[hbLen])) hbLen++;
    if (hbLen >= 2 && (hbLen % 2) == 0) {
        hexbytes = std::string(after.substr(0, hbLen));
        for (auto &c : hexbytes) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        after = after.substr(hbLen);
        after = ltrimView(after);
        if (after.empty()) return std::nullopt;
        mnemonic = std::string(after);
    } else {
        auto hb = hexBytesFromDbOperands(v);
        if (!hb) return std::nullopt;
        hexbytes = *hb;
        mnemonic = std::string(after);
    }

    mnemonic = normalizeHexLiteralsForWasm(mnemonic);

    // Skip obvious non-instruction payloads (e.g. string literals after a '|' column).
    {
        auto mtrim = ltrimView(std::string_view(mnemonic));
        if (mtrim.empty() || !isAlpha(mtrim[0])) {
            return std::nullopt;
        }
    }

    // Skip plain "db" pseudo-mnemonic.
    {
        auto mtrim = ltrimView(std::string_view(mnemonic));
        if (startsWith(mtrim, "db") && (mtrim.size() == 2 || mtrim[2] == ' ' || mtrim[2] == '\t')) {
            return std::nullopt;
        }
    }

    Candidate c;
    c.lineIndex = lineIndex;
    c.indent = std::move(indent);
    c.addr8 = std::move(addr8);
    c.hexbytes = std::move(hexbytes);
    c.mnemonic = std::move(mnemonic);
    c.originalLine = line;
    return c;
}

static std::unordered_set<std::string> findNeededLabels(const std::vector<Candidate> &cands, const std::vector<std::string> &lines) {
    std::unordered_set<std::string> needed;

    static const std::regex labelRef(R"(\bloc_[0-9A-Fa-f]{1,8}\b)");
    for (const auto &c : cands) {
        for (std::sregex_iterator it(c.mnemonic.begin(), c.mnemonic.end(), labelRef), end; it != end; ++it) {
            std::string name = it->str();
            needed.insert(name);
        }
    }

    // Remove labels already defined (allow trailing comments after ':').
    static const std::regex labelDef(R"(^\s*(loc_[0-9A-Fa-f]{1,8})\s*:)");
    for (const auto &l : lines) {
        std::smatch m;
        if (std::regex_search(l, m, labelDef)) {
            needed.erase(m.str(1));
        }
    }

    return needed;
}

static std::vector<uint8_t> parseHexBytes(const std::string &hex) {
    std::vector<uint8_t> out;
    if ((hex.size() % 2) != 0) return out;
    out.reserve(hex.size() / 2);
    auto nyb = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nyb(hex[i]);
        int lo = nyb(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            out.clear();
            return out;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

static std::string toHex8(uint32_t v);

static std::string renderAsm(
    const std::vector<std::string> &lines,
    const std::vector<Candidate> &cands,
    const std::vector<char> &enabledCand,
    const std::unordered_set<std::string> &neededLabels,
    uint32_t logicalOrigin
) {
    // Many real-mode DOS binaries still use 80186+/386+ opcodes (e.g., PUSH imm16 = 68 iw).
    // Dumps frequently start with `.8086`, which makes WASM reject those mnemonics.
    // We conservatively bump CPU mode to `.386` to allow those instructions.
    static const std::regex cpuDirective(R"(^\s*\.(8086|186|286)\b)", std::regex::icase);

    std::unordered_map<size_t, size_t> lineToCand;
    lineToCand.reserve(cands.size());
    for (size_t ci = 0; ci < cands.size(); ci++) {
        lineToCand[cands[ci].lineIndex] = ci;
    }

    // addr->labels (addr is org-relative: logical addr - logicalOrigin)
    std::unordered_map<std::string, std::vector<std::string>> addrToLabels;
    for (const auto &name : neededLabels) {
        if (name.size() < 5) continue; // loc_ + at least 1
        uint32_t logicalAddr = 0;
        for (size_t i = 4; i < name.size(); i++) {
            char c = name[i];
            if (!isHexChar(c)) { logicalAddr = 0; break; }
            logicalAddr *= 16;
            if (c >= '0' && c <= '9') logicalAddr += static_cast<uint32_t>(c - '0');
            else {
                c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                logicalAddr += static_cast<uint32_t>(10 + (c - 'A'));
            }
        }
        uint32_t orgAddr = (logicalAddr >= logicalOrigin) ? (logicalAddr - logicalOrigin) : logicalAddr;
        addrToLabels[toHex8(orgAddr)].push_back(name);
    }

    // Some disassemblies reference loc_ labels that don't exist as an address anchor in the db dump.
    // Define them as EQU symbols so assembly can proceed; byte-identity is still enforced by the oracle.
    std::unordered_set<std::string> presentAddrs;
    presentAddrs.reserve(cands.size());
    for (const auto &c : cands) {
        uint32_t logicalAddr = 0;
        for (char ch : c.addr8) { // 8 hex digits
            logicalAddr *= 16;
            if (ch >= '0' && ch <= '9') logicalAddr += static_cast<uint32_t>(ch - '0');
            else {
                ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
                logicalAddr += static_cast<uint32_t>(10 + (ch - 'A'));
            }
        }
        uint32_t orgAddr = (logicalAddr >= logicalOrigin) ? (logicalAddr - logicalOrigin) : logicalAddr;
        presentAddrs.insert(toHex8(orgAddr));
    }

    std::vector<std::string> equLabels;
    equLabels.reserve(neededLabels.size());
    for (const auto &name : neededLabels) {
        if (name.size() < 5) continue;
        uint32_t logicalAddr = 0;
        for (size_t i = 4; i < name.size(); i++) {
            char c = name[i];
            if (!isHexChar(c)) { logicalAddr = 0; break; }
            logicalAddr *= 16;
            if (c >= '0' && c <= '9') logicalAddr += static_cast<uint32_t>(c - '0');
            else {
                c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                logicalAddr += static_cast<uint32_t>(10 + (c - 'A'));
            }
        }
        uint32_t orgAddr = (logicalAddr >= logicalOrigin) ? (logicalAddr - logicalOrigin) : logicalAddr;
        if (presentAddrs.find(toHex8(orgAddr)) == presentAddrs.end()) equLabels.push_back(name);
    }
    std::sort(equLabels.begin(), equLabels.end());

    std::unordered_set<std::string> emitted;
    emitted.reserve(neededLabels.size());

    std::ostringstream out;

    for (const auto &lname : equLabels) {
        uint32_t logicalAddr = 0;
        for (size_t i = 4; i < lname.size(); i++) {
            char c = lname[i];
            if (!isHexChar(c)) { logicalAddr = 0; break; }
            logicalAddr *= 16;
            if (c >= '0' && c <= '9') logicalAddr += static_cast<uint32_t>(c - '0');
            else {
                c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                logicalAddr += static_cast<uint32_t>(10 + (c - 'A'));
            }
        }
        uint32_t orgAddr = (logicalAddr >= logicalOrigin) ? (logicalAddr - logicalOrigin) : logicalAddr;
        std::string addr = toHex8(orgAddr);
        const bool needs0 = !addr.empty() && std::isalpha(static_cast<unsigned char>(addr[0]));
        out << lname << " equ " << (needs0 ? "0" : "") << addr << "h\n";
        emitted.insert(lname);
    }

    for (size_t i = 0; i < lines.size(); i++) {
        const std::string &line = lines[i];

        // Normalize CPU directives so promoted mnemonics that require 80186+/386+ assemble.
        if (std::regex_search(line, cpuDirective)) {
            std::string rewritten = std::regex_replace(line, cpuDirective, ".386");
            out << rewritten << "\n";
            continue;
        }

        // If this is a db-line candidate, we can use it as an address anchor for label insertion.
        auto itCand = lineToCand.find(i);
        if (itCand != lineToCand.end()) {
            const Candidate &c = cands[itCand->second];
            uint32_t logicalAddr = 0;
            for (char ch : c.addr8) {
                logicalAddr *= 16;
                if (ch >= '0' && ch <= '9') logicalAddr += static_cast<uint32_t>(ch - '0');
                else {
                    ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
                    logicalAddr += static_cast<uint32_t>(10 + (ch - 'A'));
                }
            }
            uint32_t orgAddr = (logicalAddr >= logicalOrigin) ? (logicalAddr - logicalOrigin) : logicalAddr;
            auto it = addrToLabels.find(toHex8(orgAddr));
            if (it != addrToLabels.end()) {
                for (const auto &lname : it->second) {
                    if (emitted.insert(lname).second) {
                        out << lname << ":\n";
                    }
                }
            }

            const bool en = enabledCand[itCand->second] != 0;
            if (!en) {
                out << c.originalLine << "\n";
            } else {
                // Keep the original comment from ';' onward.
                auto semi = line.find(';');
                std::string comment;
                if (semi != std::string::npos) {
                    comment = line.substr(semi);
                }
                out << c.indent << c.mnemonic << " " << comment << "\n";
            }
            continue;
        }

        out << line << "\n";
    }

    return out.str();
}

#if defined(__unix__) || defined(__APPLE__)
static int runProcess(const std::vector<std::string> &argv) {
    if (argv.empty()) return 127;

    std::vector<char *> cargv;
    cargv.reserve(argv.size() + 1);
    for (const auto &a : argv) cargv.push_back(const_cast<char *>(a.c_str()));
    cargv.push_back(nullptr);

    pid_t pid;
    int rc = posix_spawnp(&pid, cargv[0], nullptr, nullptr, cargv.data(), environ);
    if (rc != 0) {
        return 127;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return 127;
    }

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 127;
}
#else
static int runProcess(const std::vector<std::string> &argv) {
    // Fallback: very minimal.
    std::ostringstream cmd;
    for (const auto &a : argv) {
        cmd << '"' << a << '"' << ' ';
    }
    return std::system(cmd.str().c_str());
}
#endif

static bool assembleLinkCompare(
    const Options &opt,
    const std::string &asmText,
    const fs::path &workdir
) {
    fs::path asmPath = workdir / "promote.asm";
    fs::path objPath = workdir / "promote.obj";
    fs::path outPath = workdir / "promote.bin";

    writeStringToFile(asmPath, asmText);

    {
        std::vector<std::string> args;
        args.push_back(opt.wasm);
        args.push_back("-zq");
        if (opt.wasmWarnLevel >= 0) args.push_back("-w=" + std::to_string(opt.wasmWarnLevel));
        args.push_back("-fo=" + objPath.string());
        args.push_back(asmPath.string());
        int rc = runProcess(args);
        if (rc != 0) return false;
    }

    {
        std::vector<std::string> args;
        args.push_back(opt.wlink);
        args.push_back("option");
        args.push_back("quiet");
        args.push_back("format");
        args.push_back("raw");
        args.push_back("bin");
        args.push_back("name");
        args.push_back(outPath.string());
        args.push_back("file");
        args.push_back(objPath.string());
        int rc = runProcess(args);
        if (rc != 0) return false;
    }

    return bytesEqualFiles(opt.origBin, outPath);
}

static std::optional<std::vector<uint8_t>> assembleAndExtractBytesWdis(
    const Options &opt,
    const std::string &mnemonic,
    size_t expectedLen,
    const fs::path &workdir
) {
    // Assemble a tiny snippet so we can disassemble the .obj and extract the encoded bytes.
    // This is much cheaper than linking a full raw binary for every trial.
    fs::path asmPath = workdir / "one.asm";
    fs::path objPath = workdir / "one.obj";
    fs::path lstPath = workdir / "one.wdis.lst";

    std::ostringstream asmText;
    asmText << ".386\n";
    asmText << "_TEXT segment use16\n";
    asmText << "assume cs:_TEXT, ds:_TEXT, es:_TEXT, ss:_TEXT\n";
    asmText << "org 0000h\n";
    asmText << "start:\n";
    asmText << "    " << mnemonic << "\n";
    asmText << "_TEXT ends\n";
    asmText << "end start\n";

    writeStringToFile(asmPath, asmText.str());

    {
        std::vector<std::string> args;
        args.push_back(opt.wasm);
        args.push_back("-zq");
        if (opt.wasmWarnLevel >= 0) args.push_back("-w=" + std::to_string(opt.wasmWarnLevel));
        args.push_back("-fo=" + objPath.string());
        args.push_back(asmPath.string());
        int rc = runProcess(args);
        if (rc != 0) return std::nullopt;
    }

    {
        std::vector<std::string> args;
        args.push_back(opt.wdis);
        args.push_back("-l=" + lstPath.string());
        args.push_back(objPath.string());
        int rc = runProcess(args);
        if (rc != 0) return std::nullopt;
    }

    // Parse the listing for the first instruction line at offset 0000.
    std::ifstream f(lstPath);
    if (!f) return std::nullopt;

    std::string line;
    while (std::getline(f, line)) {
        // Example: "0000  8C C8                             mov ax,cs"
        if (line.size() < 6) continue;
        if (!(line.rfind("0000", 0) == 0)) continue;

        std::istringstream iss(line);
        std::string offTok;
        iss >> offTok;
        if (offTok != "0000") continue;

        std::vector<uint8_t> bytes;
        bytes.reserve(expectedLen);
        while (bytes.size() < expectedLen) {
            std::string bt;
            if (!(iss >> bt)) break;
            if (bt.size() != 2 || !isHexChar(bt[0]) || !isHexChar(bt[1])) break;
            auto v = parseHexBytes(bt);
            if (v.size() != 1) break;
            bytes.push_back(v[0]);
        }

        if (bytes.size() == expectedLen) return bytes;
        return std::nullopt;
    }

    return std::nullopt;
}

static uint32_t detectLogicalOrigin(const std::vector<std::string> &lines) {
    // BIN16 db dumps usually start with e.g.:
    //   ; Origin: 0100h
    //   ; logical origin: 0100h
    // and then use `org 0000h`.
    static const std::regex re1(R"(^\s*;\s*logical\s+origin:\s*([0-9A-Fa-f]+)h\b)");
    static const std::regex re2(R"(^\s*;\s*Origin:\s*([0-9A-Fa-f]+)h\b)");
    for (size_t i = 0; i < std::min<size_t>(lines.size(), 256); i++) {
        std::smatch m;
        if (std::regex_search(lines[i], m, re1) || std::regex_search(lines[i], m, re2)) {
            std::string hex = m.str(1);
            uint32_t v = 0;
            for (char c : hex) {
                if (!isHexChar(c)) return 0;
                v *= 16;
                if (c >= '0' && c <= '9') v += static_cast<uint32_t>(c - '0');
                else {
                    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                    v += static_cast<uint32_t>(10 + (c - 'A'));
                }
            }
            return v;
        }
    }
    return 0;
}

static std::string toHex8(uint32_t v) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << (v & 0xFFFFFFFFu);
    return oss.str();
}

struct WdisBatchItem {
    std::string mnemonic;
    size_t expectedLen = 0;
    uint16_t org = 0;
};

static std::optional<std::unordered_map<uint16_t, std::vector<uint8_t>>> assembleAndExtractBytesWdisBatch(
    const Options &opt,
    const std::vector<WdisBatchItem> &items,
    const fs::path &workdir
) {
    if (items.empty()) return std::unordered_map<uint16_t, std::vector<uint8_t>>{};

    fs::path asmPath = workdir / "batch.asm";
    fs::path objPath = workdir / "batch.obj";
    fs::path lstPath = workdir / "batch.wdis.lst";

    std::ostringstream asmText;
    asmText << ".386\n";
    asmText << "_TEXT segment use16\n";
    asmText << "assume cs:_TEXT, ds:_TEXT, es:_TEXT, ss:_TEXT\n";
    asmText << "org 0000h\n";
    asmText << "start:\n";
    for (size_t i = 0; i < items.size(); i++) {
        const auto &it = items[i];
        // Place each candidate at a known offset so we can reliably parse its bytes.
        // Using org avoids relying on previous instruction lengths.
        asmText << "org " << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << it.org << "h\n";
        asmText << "L" << std::dec << i << ":\n";
        asmText << "    " << it.mnemonic << "\n";
    }
    asmText << "_TEXT ends\n";
    asmText << "end start\n";

    writeStringToFile(asmPath, asmText.str());

    {
        std::vector<std::string> args;
        args.push_back(opt.wasm);
        args.push_back("-zq");
        if (opt.wasmWarnLevel >= 0) args.push_back("-w=" + std::to_string(opt.wasmWarnLevel));
        args.push_back("-fo=" + objPath.string());
        args.push_back(asmPath.string());
        int rc = runProcess(args);
        if (rc != 0) return std::nullopt;
    }

    {
        std::vector<std::string> args;
        args.push_back(opt.wdis);
        args.push_back("-l=" + lstPath.string());
        args.push_back(objPath.string());
        int rc = runProcess(args);
        if (rc != 0) return std::nullopt;
    }

    std::unordered_map<uint16_t, size_t> wantLen;
    wantLen.reserve(items.size());
    for (const auto &it : items) {
        if (it.expectedLen == 0) continue;
        wantLen[it.org] = it.expectedLen;
    }

    std::unordered_map<uint16_t, std::vector<uint8_t>> out;
    out.reserve(items.size());

    std::ifstream f(lstPath);
    if (!f) return std::nullopt;

    std::string line;
    while (std::getline(f, line)) {
        if (line.size() < 4) continue;
        if (!isHexChar(line[0]) || !isHexChar(line[1]) || !isHexChar(line[2]) || !isHexChar(line[3])) continue;

        std::string offTok = line.substr(0, 4);
        uint16_t off = 0;
        {
            unsigned v = 0;
            for (char c : offTok) {
                v *= 16;
                if (c >= '0' && c <= '9') v += static_cast<unsigned>(c - '0');
                else {
                    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                    v += static_cast<unsigned>(10 + (c - 'A'));
                }
            }
            off = static_cast<uint16_t>(v & 0xFFFFu);
        }

        auto itWant = wantLen.find(off);
        if (itWant == wantLen.end()) continue;
        size_t expectedLen = itWant->second;

        std::istringstream iss(line);
        std::string off2;
        iss >> off2;
        if (off2.size() != 4) continue;

        std::vector<uint8_t> bytes;
        bytes.reserve(expectedLen);
        while (bytes.size() < expectedLen) {
            std::string bt;
            if (!(iss >> bt)) break;
            if (bt.size() != 2 || !isHexChar(bt[0]) || !isHexChar(bt[1])) break;
            auto v = parseHexBytes(bt);
            if (v.size() != 1) break;
            bytes.push_back(v[0]);
        }

        if (bytes.size() == expectedLen) {
            out.emplace(off, std::move(bytes));
        }
    }

    return out;
}

static fs::path makeTempDir() {
    auto base = fs::temp_directory_path();
    for (int i = 0; i < 1000; i++) {
        auto p = base / ("dosre-promote-" + std::to_string(::getpid()) + "-" + std::to_string(i));
        std::error_code ec;
        if (fs::create_directory(p, ec)) return p;
    }
    die("failed to create temp directory");
    return {};
}

struct PromoteState {
    const Options *opt{};
    const std::vector<std::string> *lines{};
    const std::vector<Candidate> *cands{};
    const std::unordered_set<std::string> *neededLabels{};
    fs::path workdir;

    std::vector<char> enabled; // per-candidate

    uint64_t tries = 0;
    std::chrono::steady_clock::time_point started;
    std::chrono::steady_clock::time_point lastReport;

    void report(bool force) {
        auto now = std::chrono::steady_clock::now();
        if (!force && std::chrono::duration_cast<std::chrono::milliseconds>(now - lastReport).count() < 2000) return;
        lastReport = now;

        double elapsed = std::max(0.001, std::chrono::duration<double>(now - started).count());
        double rate = static_cast<double>(tries) / elapsed;

        size_t enabledCount = 0;
        for (auto b : enabled) enabledCount += (b != 0);

        std::cerr << "progress: enabled " << enabledCount << "/" << enabled.size() << " lines, tries=" << tries
                  << ", " << std::fixed << std::setprecision(2) << rate << " asm/s, elapsed=" << std::setprecision(1)
                  << elapsed << "s\n";
    }
};

static void tryEnableGroup(PromoteState &st, const std::vector<size_t> &group) {
    if (group.empty()) return;

    // Save previous state for the group.
    std::vector<size_t> changed;
    changed.reserve(group.size());
    for (auto cid : group) {
        if (cid < st.enabled.size() && st.enabled[cid] == 0) {
            st.enabled[cid] = 1;
            changed.push_back(cid);
        }
    }

    st.tries++;
    // NOTE: slow oracle is only used for label-dependent candidates; renderAsm already accounts
    // for logical origin when placing label anchors.
    uint32_t logicalOrigin = detectLogicalOrigin(*st.lines);
    std::string asmText = renderAsm(*st.lines, *st.cands, st.enabled, *st.neededLabels, logicalOrigin);
    bool ok = assembleLinkCompare(*st.opt, asmText, st.workdir);
    st.report(false);

    if (ok) {
        return; // keep changes
    }

    // revert
    for (auto cid : changed) st.enabled[cid] = 0;

    if (group.size() == 1) {
        // fail single
        return;
    }

    // split
    size_t mid = group.size() / 2;
    std::vector<size_t> left(group.begin(), group.begin() + static_cast<long>(mid));
    std::vector<size_t> right(group.begin() + static_cast<long>(mid), group.end());
    tryEnableGroup(st, left);
    tryEnableGroup(st, right);
}

static void usage() {
    std::cerr
        << "bin16_promote_wasm --in input.asm --orig original.bin --out promoted.asm [options]\n"
        << "Options:\n"
        << "  --wasm PATH       (default: wasm)\n"
        << "  --wlink PATH      (default: wlink)\n"
        << "  --wdis PATH       (default: wdis)\n"
        << "  --chunk N         (default: 1024)\n"
    << "  --jobs N          (default: 1)\n"
    << "  --wasm-warn-level N  (default: tool default; 0 silences warnings)\n"
        << "  --quiet\n"
        << "  --keep-workdir\n";
}

static Options parseArgs(int argc, char **argv) {
    Options o;
    for (int i = 1; i < argc; i++) {
        std::string a(argv[i]);
        auto need = [&](const char *name) -> std::string {
            if (i + 1 >= argc) die(std::string("missing value for ") + name);
            return std::string(argv[++i]);
        };

        if (a == "--in") o.inAsm = need("--in");
        else if (a == "--orig") o.origBin = need("--orig");
        else if (a == "--out") o.outAsm = need("--out");
        else if (a == "--wasm") o.wasm = need("--wasm");
        else if (a == "--wlink") o.wlink = need("--wlink");
        else if (a == "--wdis") o.wdis = need("--wdis");
        else if (a == "--chunk") o.chunk = std::stoi(need("--chunk"));
        else if (a == "--jobs") o.jobs = std::stoi(need("--jobs"));
        else if (a == "--wasm-warn-level") o.wasmWarnLevel = std::stoi(need("--wasm-warn-level"));
        else if (a == "--quiet") o.quiet = true;
        else if (a == "--keep-workdir") o.keepWorkdir = true;
        else if (a == "-h" || a == "--help") {
            usage();
            std::exit(0);
        } else {
            die("unknown arg: " + a);
        }
    }

    if (o.inAsm.empty() || o.origBin.empty() || o.outAsm.empty()) {
        usage();
        die("--in/--orig/--out are required");
    }

    return o;
}

int main(int argc, char **argv) {
    Options opt = parseArgs(argc, argv);

    if (!fileExists(opt.inAsm)) die("missing --in file: " + opt.inAsm);
    if (!fileExists(opt.origBin)) die("missing --orig file: " + opt.origBin);

    auto lines = readFileLines(opt.inAsm);
    uint32_t logicalOrigin = detectLogicalOrigin(lines);

    std::vector<Candidate> cands;
    cands.reserve(lines.size());
    for (size_t i = 0; i < lines.size(); i++) {
        auto cand = parseDbLineCandidate(lines[i], i);
        if (cand) {
            static const std::regex labelRef(R"(\bloc_[0-9A-Fa-f]{1,8}\b)");
            cand->hasLocLabelRef = std::regex_search(cand->mnemonic, labelRef);
            cands.push_back(std::move(*cand));
        }
    }

    auto neededLabels = findNeededLabels(cands, lines);

    std::cerr << "Found " << cands.size() << " promotable db-lines\n";
    std::cerr << "Need " << neededLabels.size() << " labels\n";

    PromoteState st;
    st.opt = &opt;
    st.lines = &lines;
    st.cands = &cands;
    st.neededLabels = &neededLabels;
    st.workdir = makeTempDir();
    st.enabled.assign(cands.size(), 0);
    st.started = std::chrono::steady_clock::now();
    st.lastReport = st.started;

    // Baseline must work (full-file oracle).
    {
        st.tries++;
        std::string baseAsm = renderAsm(lines, cands, st.enabled, neededLabels, logicalOrigin);
        bool ok = assembleLinkCompare(opt, baseAsm, st.workdir);
        if (!ok) {
            die("Baseline (all db) did not assemble+match; cannot promote. (Check wasm/wlink on PATH and that the dump is WASM-compatible.)");
        }
    }

    // Fast path: per-instruction validation via wasm+wdis for candidates without loc_ label refs.
    // This matches the intended workflow: try replace, check byte equality, keep if equal.
    size_t fastOk = 0;
    size_t fastTried = 0;
    {
        if (opt.jobs < 1) opt.jobs = 1;

        std::vector<size_t> fastIds;
        fastIds.reserve(cands.size());
        for (size_t ci = 0; ci < cands.size(); ci++) {
            if (cands[ci].hasLocLabelRef) continue;
            auto expected = parseHexBytes(cands[ci].hexbytes);
            if (expected.empty()) continue;
            fastIds.push_back(ci);
        }

        fastTried = fastIds.size();
        if (opt.jobs == 1) {
            std::unordered_map<std::string, std::vector<uint8_t>> cache;
            cache.reserve(1024);

            for (size_t idx = 0; idx < fastIds.size(); idx++) {
                size_t ci = fastIds[idx];
                auto expected = parseHexBytes(cands[ci].hexbytes);
                if (expected.empty()) continue;
                std::string key = cands[ci].mnemonic + "#" + std::to_string(expected.size());

                std::optional<std::vector<uint8_t>> got;
                auto it = cache.find(key);
                if (it != cache.end()) {
                    got = it->second;
                } else {
                    got = assembleAndExtractBytesWdis(opt, cands[ci].mnemonic, expected.size(), st.workdir);
                    if (got) cache.emplace(key, *got);
                }

                if (got && *got == expected) {
                    st.enabled[ci] = 1;
                    fastOk++;
                }

                st.tries++;
                st.report(false);
            }
            st.report(true);
        } else {
            // Parallelize the fast oracle: each worker gets its own directory to avoid file collisions.
            // Also cache mnemonic->bytes so repeated patterns don't respawn wasm+wdis.
            std::atomic<size_t> next{0};
            std::atomic<size_t> ok{0};
            std::atomic<size_t> tried{0};
            std::mutex cacheMu;
            std::unordered_map<std::string, std::vector<uint8_t>> cache;
            cache.reserve(4096);

            int jobs = opt.jobs;
            if (jobs > static_cast<int>(fastIds.size())) jobs = static_cast<int>(fastIds.size());
            if (jobs < 1) jobs = 1;

            std::vector<std::thread> threads;
            threads.reserve(static_cast<size_t>(jobs));

            for (int t = 0; t < jobs; t++) {
                threads.emplace_back([&, t]() {
                    fs::path tdir = st.workdir / ("fast-" + std::to_string(t));
                    std::error_code ec;
                    fs::create_directory(tdir, ec);

                    constexpr size_t kBatchMax = 128;
                    constexpr uint16_t kStride = 0x40; // big enough to avoid overlap even for long encodings

                    while (true) {
                        // Pull a batch of work.
                        std::array<size_t, kBatchMax> batchIdx{};
                        size_t batchN = 0;
                        for (; batchN < kBatchMax; batchN++) {
                            size_t idx = next.fetch_add(1, std::memory_order_relaxed);
                            if (idx >= fastIds.size()) break;
                            batchIdx[batchN] = idx;
                        }
                        if (batchN == 0) break;

                        // First resolve any cached mnemonics; accumulate the rest into a batch assemble.
                        std::vector<WdisBatchItem> batch;
                        batch.reserve(batchN);
                        std::array<size_t, kBatchMax> batchCi{};
                        std::array<size_t, kBatchMax> batchExpectedLen{};
                        size_t batchCount = 0;

                        for (size_t bi = 0; bi < batchN; bi++) {
                            size_t ci = fastIds[batchIdx[bi]];
                            auto expected = parseHexBytes(cands[ci].hexbytes);
                            if (expected.empty()) {
                                tried.fetch_add(1, std::memory_order_relaxed);
                                continue;
                            }

                            std::string key = cands[ci].mnemonic + "#" + std::to_string(expected.size());
                            bool hit = false;
                            {
                                std::lock_guard<std::mutex> lock(cacheMu);
                                auto it = cache.find(key);
                                if (it != cache.end()) {
                                    hit = true;
                                    if (it->second == expected) {
                                        st.enabled[ci] = 1;
                                        ok.fetch_add(1, std::memory_order_relaxed);
                                    }
                                }
                            }
                            if (hit) {
                                tried.fetch_add(1, std::memory_order_relaxed);
                                continue;
                            }

                            WdisBatchItem it;
                            it.mnemonic = cands[ci].mnemonic;
                            it.expectedLen = expected.size();
                            it.org = static_cast<uint16_t>((batchCount * kStride) & 0xFFFFu);
                            batch.push_back(it);
                            batchCi[batchCount] = ci;
                            batchExpectedLen[batchCount] = expected.size();
                            batchCount++;
                        }

                        if (batchCount == 0) continue;

                        auto gotMap = assembleAndExtractBytesWdisBatch(opt, batch, tdir);
                        if (!gotMap) {
                            // Fallback: run per-instruction for robustness.
                            for (size_t i = 0; i < batchCount; i++) {
                                size_t ci = batchCi[i];
                                auto expected = parseHexBytes(cands[ci].hexbytes);
                                auto got = assembleAndExtractBytesWdis(opt, cands[ci].mnemonic, expected.size(), tdir);
                                std::string key = cands[ci].mnemonic + "#" + std::to_string(expected.size());
                                if (got) {
                                    std::lock_guard<std::mutex> lock(cacheMu);
                                    cache.emplace(key, *got);
                                }
                                if (got && *got == expected) {
                                    st.enabled[ci] = 1;
                                    ok.fetch_add(1, std::memory_order_relaxed);
                                }
                                tried.fetch_add(1, std::memory_order_relaxed);
                            }
                            continue;
                        }

                        for (size_t i = 0; i < batchCount; i++) {
                            size_t ci = batchCi[i];
                            auto expected = parseHexBytes(cands[ci].hexbytes);
                            uint16_t org = static_cast<uint16_t>((i * kStride) & 0xFFFFu);
                            std::string key = cands[ci].mnemonic + "#" + std::to_string(expected.size());

                            auto it = gotMap->find(org);
                            if (it != gotMap->end()) {
                                {
                                    std::lock_guard<std::mutex> lock(cacheMu);
                                    cache.emplace(key, it->second);
                                }
                                if (it->second == expected) {
                                    st.enabled[ci] = 1;
                                    ok.fetch_add(1, std::memory_order_relaxed);
                                }
                            }
                            tried.fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                });
            }

            for (auto &th : threads) th.join();
            fastOk = ok.load(std::memory_order_relaxed);
            // Keep the overall try counter roughly meaningful.
            st.tries += tried.load(std::memory_order_relaxed);
            st.report(true);
        }
    }
    if (!opt.quiet) {
        std::cerr << "Fast path: accepted " << fastOk << "/" << fastTried << " mnemonics (wdis oracle";
        if (opt.jobs > 1) std::cerr << ", jobs=" << opt.jobs;
        std::cerr << ")\n";
    }

    // Slow path: remaining candidates (typically loc_ branches) still require the full-file oracle.
    // Use chunk+bisection but only over the remaining candidates to keep runtime reasonable.
    if (opt.chunk <= 0) opt.chunk = 1024;
    std::vector<size_t> slowIds;
    slowIds.reserve(cands.size());
    for (size_t ci = 0; ci < cands.size(); ci++) {
        if (st.enabled[ci]) continue;
        // Only a small remainder should need the slow full-file oracle now.
        // We reserve it for candidates where we couldn't validate bytes via wdis.
        if (!cands[ci].hasLocLabelRef) continue;
        slowIds.push_back(ci);
    }

    for (size_t i = 0; i < slowIds.size(); i += static_cast<size_t>(opt.chunk)) {
        size_t end = std::min(slowIds.size(), i + static_cast<size_t>(opt.chunk));
        std::vector<size_t> group(slowIds.begin() + static_cast<long>(i), slowIds.begin() + static_cast<long>(end));
        tryEnableGroup(st, group);
        st.report(true);
    }

    // Final write
    std::string outAsmText = renderAsm(lines, cands, st.enabled, neededLabels, logicalOrigin);
    {
        std::ofstream f(opt.outAsm, std::ios::binary);
        if (!f) die("failed to write: " + opt.outAsm);
        f.write(outAsmText.data(), static_cast<std::streamsize>(outAsmText.size()));
    }

    size_t enabledCount = 0;
    size_t enabledBytes = 0;
    for (size_t ci = 0; ci < cands.size(); ci++) {
        if (st.enabled[ci]) {
            enabledCount++;
            enabledBytes += cands[ci].hexbytes.size() / 2;
        }
    }

    std::cerr << "Wrote " << opt.outAsm << "\n";
    std::cerr << "Enabled " << enabledCount << "/" << cands.size() << " mnemonics (" << enabledBytes << " bytes worth)\n";

    // Final end-to-end validation (full-file oracle) to catch any corner case.
    if (!opt.quiet) {
        std::cerr << "Validating final output via full rebuild...\n";
    }
    {
        st.tries++;
        bool ok = assembleLinkCompare(opt, outAsmText, st.workdir);
        if (!ok) {
            die("Final full rebuild did not match original bytes. (This usually means a label-based branch encoding differs.)");
        }
    }

    if (!opt.keepWorkdir) {
        std::error_code ec;
        fs::remove_all(st.workdir, ec);
    } else {
        std::cerr << "Note: kept workdir " << st.workdir.string() << "\n";
    }

    return 0;
}
