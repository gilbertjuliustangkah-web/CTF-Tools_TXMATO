"""
CTF Toolkit - Tool catalog and manager.

A curated list of well-known CTF tools (inspired by zardus/ctf-tools),
grouped by category, with status detection and install/uninstall helpers.

Installers only ever run argv lists built from this module's static catalog
(no shell, no user-supplied values), so a web request cannot inject commands.
"""
import importlib.util
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from ctf.core.process import run
from ctf.core.workspace import WORKSPACE_ROOT

TOOLS_DIR = WORKSPACE_ROOT / "tools"
TOOLS_DIR.mkdir(parents=True, exist_ok=True)

CATEGORY_LABELS = {
    "binary":    "Binary / Reversing",
    "forensics": "Forensics",
    "crypto":    "Crypto",
    "web":       "Web",
    "recon":     "Recon",
    "stego":     "Stegano",
    "osint":     "OSINT",
    "pentes":    "Penetration Testing",
    "misc":      "Misc",
}


@dataclass(frozen=True)
class ToolEntry:
    id: str
    category: str
    name: str
    description: str
    url: str = ""
    source: str = "manual"          # pip | apt | git | docker | manual
    pip_pkg: str | None = None
    apt_pkg: str | None = None
    git_url: str | None = None
    bin_name: str | None = None
    python_module: str | None = None
    docker_image: str | None = None
    os: str = "all"                 # all | linux | windows | posix
    setup: list[str] = field(default_factory=list)
    install_hint: str = ""

    @property
    def supported_here(self) -> bool:
        if self.os == "all":
            return True
        if self.os == "windows":
            return sys.platform.startswith("win")
        if self.os == "linux":
            return sys.platform.startswith("linux")
        if self.os == "posix":
            return not sys.platform.startswith("win")
        return True

    @property
    def install_cmd(self) -> list[str]:
        """Human-inspectable argv used to install this tool."""
        if self.source == "pip" and self.pip_pkg:
            return [sys.executable, "-m", "pip", "install", self.pip_pkg]
        if self.source == "apt" and self.apt_pkg:
            return ["sudo", "apt-get", "install", "-y", self.apt_pkg]
        if self.source == "git" and self.git_url:
            return ["git", "clone", "--depth", "1", self.git_url, str(self._dest())]
        if self.source == "docker" and self.docker_image:
            return ["docker", "pull", self.docker_image]
        return []

    def _dest(self) -> Path:
        return TOOLS_DIR / self.id


_RAW = [
    # ── Binary / Reversing ────────────────────────────────────────────────
    dict(id="pwntools", category="binary", name="Pwntools",
         description="Python exploit-development / CTF utility library.",
         source="pip", pip_pkg="pwntools", python_module="pwn", bin_name="pwn",
         url="https://github.com/Gallopsled/pwntools"),
    dict(id="angr", category="binary", name="Angr",
         description="Binary analysis engine (symbolic execution, CFG, …).",
         source="pip", pip_pkg="angr", python_module="angr",
         url="http://angr.io"),
    dict(id="ropper", category="binary", name="Ropper",
         description="ROP gadget finder and chain builder.",
         source="pip", pip_pkg="ropper", python_module="ropper", bin_name="ropper",
         url="https://github.com/sashs/Ropper"),
    dict(id="ropgadget", category="binary", name="ROPgadget",
         description="Simple gadget finder for ROP exploitation.",
         source="pip", pip_pkg="ROPgadget", python_module="ROPgadget", bin_name="ROPgadget",
         url="https://github.com/JonathanSalwan/ROPgadget"),
    dict(id="capstone", category="binary", name="Capstone",
         description="Multi-architecture disassembly framework.",
         source="pip", pip_pkg="capstone", python_module="capstone",
         url="https://www.capstone-engine.org"),
    dict(id="checksec", category="binary", name="Checksec",
         description="Check binary hardening (PIE, NX, RELRO, canary, …).",
         source="git", git_url="https://github.com/slimm609/checksec.sh",
         python_module="checksec", bin_name="checksec",
         url="https://github.com/slimm609/checksec.sh"),
    dict(id="radare2", category="binary", name="Radare2",
         description="Reverse engineering framework + CLI disassembler.",
         source="apt", apt_pkg="radare2", bin_name="r2", os="linux",
         url="https://radare.org",
         install_hint="Windows: scoop install radare2"),
    dict(id="ghidra", category="binary", name="Ghidra",
         description="NSA's open-source reverse engineering / decompiler suite.",
         source="manual", bin_name="analyzeHeadless",
         url="https://ghidra-sre.org",
         install_hint="Download from ghidra-sre.org and install manually."),
    dict(id="objdump", category="binary", name="Binutils (objdump)",
         description="objdump / strings / readelf — standard binary inspection.",
         source="apt", apt_pkg="binutils", bin_name="objdump", os="posix",
         url="https://www.gnu.org/software/binutils/",
         install_hint="Windows: scoop install binutils"),
    dict(id="gdb", category="binary", name="GDB",
         description="GNU debugger (with pwndbg/gef plugins).",
         source="apt", apt_pkg="gdb", bin_name="gdb", os="linux",
         url="https://www.gnu.org/software/gdb/",
         install_hint="Windows: use WSL or scoop install gdb"),
    dict(id="pwndbg", category="binary", name="Pwndbg",
         description="Enhanced GDB environment for pwning.",
         source="git", git_url="https://github.com/pwndbg/pwndbg",
         setup=["./setup.sh"], os="linux",
         url="https://github.com/pwndbg/pwndbg"),
    dict(id="gef", category="binary", name="GEF",
         description="GDB enhanced features (one-file, easy install).",
         source="git", git_url="https://github.com/hugsy/gef",
         setup=["bash", "gef.sh"], os="posix",
         url="https://github.com/hugsy/gef"),
    dict(id="one_gadget", category="binary", name="OneGadget",
         description="Find one-gadget RCE in libc.",
         source="manual", bin_name="one_gadget", os="linux",
         url="https://github.com/david942j/one_gadget",
         install_hint="gem install one_gadget"),
    dict(id="valgrind", category="binary", name="Valgrind",
         description="Dynamic binary instrumentation (memcheck, …).",
         source="apt", apt_pkg="valgrind", bin_name="valgrind", os="linux",
         url="https://valgrind.org"),
    dict(id="qemu", category="binary", name="QEMU user",
         description="Run cross-arch binaries (arm/mips/… challenges).",
         source="apt", apt_pkg="qemu-user-static", bin_name="qemu-x86_64", os="linux",
         url="https://qemu.org"),
    dict(id="uncompyle6", category="binary", name="uncompyle6",
         description="Python bytecode decompiler (pyc -> source).",
         source="pip", pip_pkg="uncompyle6", python_module="uncompyle6", bin_name="uncompyle6",
         url="https://github.com/rocky/python-uncompyle6"),
    dict(id="pyelftools", category="binary", name="pyelftools",
         description="Pure-python parsing of ELF binaries and sections.",
         source="pip", pip_pkg="pyelftools", python_module="elftools",
         url="https://github.com/eliben/pyelftools"),
    dict(id="strace", category="binary", name="strace",
         description="Trace syscalls and signals of a running process.",
         source="apt", apt_pkg="strace", bin_name="strace", os="linux",
         url="https://strace.io"),
    dict(id="upx", category="binary", name="UPX",
         description="Pack/unpack executables; spot packed binaries fast.",
         source="apt", apt_pkg="upx-ucl", bin_name="upx", os="posix",
         url="https://upx.github.io",
         install_hint="Windows: scoop install upx"),
    dict(id="shellnoob", category="binary", name="shellnoob",
         description="Shellcode maker/encoder helper (find gadgets, assemble).",
         source="git", git_url="https://github.com/reyammer/shellnoob",
         setup=["make", "install"], os="linux",
         url="https://github.com/reyammer/shellnoob"),

    # ── Forensics ────────────────────────────────────────────────────────
    dict(id="binwalk", category="forensics", name="Binwalk",
         description="Firmware / file analysis and carving (magic signatures).",
         source="pip", pip_pkg="binwalk", python_module="binwalk", bin_name="binwalk",
         url="https://github.com/ReFirmLabs/binwalk"),
    dict(id="volatility3", category="forensics", name="Volatility 3",
         description="Memory forensics on RAM dumps.",
         source="pip", pip_pkg="volatility3", python_module="volatility3", bin_name="vol",
         url="https://github.com/volatilityfoundation/volatility3"),
    dict(id="exiftool", category="forensics", name="ExifTool",
         description="Read/write metadata in images, PDFs, office files, …",
         source="apt", apt_pkg="libimage-exiftool-perl", bin_name="exiftool", os="posix",
         url="https://exiftool.org",
         install_hint="Windows: scoop install exiftool"),
    dict(id="oletools", category="forensics", name="oletools",
         description="Analyze OLE / VBA macros in office files (olevba).",
         source="pip", pip_pkg="oletools", python_module="oletools",
         url="https://github.com/decalage2/oletools"),
    dict(id="pdf-parser", category="forensics", name="pdf-parser",
         description="Dig into PDF objects without rendering.",
         source="manual", bin_name="pdf-parser", os="posix",
         url="https://blog.didierstevens.com/programs/pdf-tools/",
         install_hint="git clone tools.didierstevens / pip install pdfparser"),
    dict(id="foremost", category="forensics", name="Foremost",
         description="File carver using headers/footers.",
         source="apt", apt_pkg="foremost", bin_name="foremost", os="linux",
         url="https://foremost.sourceforge.net"),
    dict(id="testdisk", category="forensics", name="TestDisk / PhotoRec",
         description="Deleted-file recovery and partition repair.",
         source="apt", apt_pkg="testdisk", bin_name="testdisk", os="linux",
         url="https://www.cgsecurity.org/wiki/TestDisk"),
    dict(id="pngcheck", category="forensics", name="pngcheck",
         description="Verify and dump PNG (and other image) internals.",
         source="apt", apt_pkg="pngcheck", bin_name="pngcheck", os="posix",
         url="https://launchpad.net/ubuntu/+source/pngtools"),
    dict(id="xxd", category="forensics", name="xxd",
         description="Hex dump / reverse of binary data.",
         source="apt", apt_pkg="xxd", bin_name="xxd", os="linux",
         url="https://www.vim.org"),
    dict(id="strings", category="forensics", name="strings",
         description="Extract printable strings from binary data.",
         source="apt", apt_pkg="binutils", bin_name="strings", os="linux",
         url="https://www.gnu.org/software/binutils/"),
    dict(id="sleuthkit", category="forensics", name="The Sleuth Kit",
         description="Disk image forensics: file listing, recovery, timeline.",
         source="apt", apt_pkg="sleuthkit", bin_name="fls", os="linux",
         url="https://www.sleuthkit.org/sleuthkit/"),
    dict(id="bulk_extractor", category="forensics", name="bulk_extractor",
         description="High-speed carve of emails, URLs, crypto keys, …",
         source="apt", apt_pkg="bulk-extractor", bin_name="bulk_extractor", os="linux",
         url="https://github.com/simsong/bulk_extractor"),
    dict(id="hashdeep", category="forensics", name="hashdeep",
         description="Recursive file hashing (md5/sha1/sha256) and audit.",
         source="apt", apt_pkg="hashdeep", bin_name="hashdeep", os="posix",
         url="https://github.com/jessek/hashdeep"),
    dict(id="yara", category="forensics", name="YARA",
         description="Rule-based malware/file pattern matching.",
         source="pip", pip_pkg="yara-python", python_module="yara",
         url="https://virustotal.github.io/yara/"),
    dict(id="qpdf", category="forensics", name="qpdf",
         description="Transform/repair/add features to PDF documents.",
         source="apt", apt_pkg="qpdf", bin_name="qpdf", os="posix",
         url="https://qpdf.sourceforge.io"),
    dict(id="poppler-utils", category="forensics", name="poppler-utils",
         description="pdftotext / pdfinfo / pdfimages for PDF mining.",
         source="apt", apt_pkg="poppler-utils", bin_name="pdftotext", os="posix",
         url="https://poppler.freedesktop.org/"),
    dict(id="exiv2", category="forensics", name="exiv2",
         description="Exif/IPTC/XMP metadata read/write for images.",
         source="apt", apt_pkg="exiv2", bin_name="exiv2", os="posix",
         url="https://exiv2.org",
         install_hint="Windows: scoop install exiv2"),

    # ── Crypto ───────────────────────────────────────────────────────────
    dict(id="rsactftool", category="crypto", name="RsaCtfTool",
         description="RSA attacks: wiener, fermat, common modulus, hastad, …",
         source="git", git_url="https://github.com/RsaCtfTool/RsaCtfTool",
         setup=["python", "-m", "pip", "install", "-r", "requirements.txt"],
         bin_name="RsaCtfTool",
         url="https://github.com/RsaCtfTool/RsaCtfTool"),
    dict(id="xortool", category="crypto", name="XORtool",
         description="Guess XOR key length and recover message.",
         source="pip", pip_pkg="xortool", python_module="xortool", bin_name="xortool",
         url="https://github.com/hellman/xortool"),
    dict(id="hashid", category="crypto", name="HashID",
         description="Identify hash types from a hash string.",
         source="pip", pip_pkg="hashid", python_module="hashid", bin_name="hashid",
         url="https://github.com/psypanda/hashID"),
    dict(id="hashcat", category="crypto", name="Hashcat",
         description="Advanced password recovery / hash cracking (GPU).",
         source="apt", apt_pkg="hashcat", bin_name="hashcat", os="posix",
         url="https://hashcat.net/hashcat/"),
    dict(id="john", category="crypto", name="John the Ripper",
         description="Password cracker for common hash/archive formats.",
         source="apt", apt_pkg="john", bin_name="john", os="posix",
         url="https://www.openwall.com/john/"),
    dict(id="z3", category="crypto", name="Z3",
         description="Microsoft theorem prover / SMT solver.",
         source="pip", pip_pkg="z3-solver", python_module="z3", bin_name="z3",
         url="https://github.com/Z3Prover/z3"),
    dict(id="pycryptodome", category="crypto", name="PyCryptodome",
         description="Python crypto primitives (RSA, AES, XOR ciphers…).",
         source="pip", pip_pkg="pycryptodome", python_module="Crypto",
         url="https://www.pycryptodome.org"),
    dict(id="gmpy2", category="crypto", name="gmpy2",
         description="GNU MP arbitrary-precision arithmetic for number theory.",
         source="pip", pip_pkg="gmpy2", python_module="gmpy2",
         url="https://gmpy2.readthedocs.io"),
    dict(id="codext", category="crypto", name="Codext",
         description="135+ encodings/decodings CLI (base*, rot*, morse, …).",
         source="pip", pip_pkg="codext", python_module="codext", bin_name="codext",
         url="https://github.com/dhondta/python-codext"),
    dict(id="openssl", category="crypto", name="OpenSSL",
         description="RSA/key extraction, certificates, ciphers.",
         source="apt", apt_pkg="openssl", bin_name="openssl", os="posix",
         url="https://www.openssl.org",
         install_hint="Windows: ships with Git for Windows."),
    dict(id="sympy", category="crypto", name="SymPy",
         description="Symbolic math (number theory, discrete logs, GF arithmetic).",
         source="pip", pip_pkg="sympy", python_module="sympy",
         url="https://www.sympy.org"),
    dict(id="factordb", category="crypto", name="FactorDB (CLI)",
         description="Factor integers via the FactorDB online service.",
         source="pip", pip_pkg="factordb-pycli", python_module="factordb",
         url="https://github.com/ryosan-470/factordb-pycli"),
    dict(id="yafu", category="crypto", name="YAFU",
         description="Modern integer factorizer (SIQS, ECM) for RSA CTFs.",
         source="manual", bin_name="yafu", os="posix",
         url="https://sourceforge.net/projects/yafu/",
         install_hint="Build from sourceforge.net/projects/yafu."),
    dict(id="gnupg", category="crypto", name="GnuPG",
         description="OpenPGP keys, signing, encryption puzzles.",
         source="apt", apt_pkg="gnupg", bin_name="gpg", os="posix",
         url="https://gnupg.org"),
    dict(id="sagemath", category="crypto", name="SageMath",
         description="Heavy-duty math system for hard number-theory challenges.",
         source="manual", bin_name="sage", os="posix",
         url="https://www.sagemath.org",
         install_hint="apt install sagemath OR use the docker image docker.io/malb/sage"),
    dict(id="pyjwt", category="crypto", name="PyJWT",
         description="Encode/decode/crack JSON Web Tokens from Python.",
         source="pip", pip_pkg="PyJWT", python_module="jwt",
         url="https://github.com/jpadilla/pyjwt"),
    dict(id="hashpump", category="crypto", name="HashPump",
         description="Length-extension attack on MD5/SHA1/… MACs.",
         source="git", git_url="https://github.com/bwall/HashPump",
         setup=["make", "install"], os="linux",
         url="https://github.com/bwall/HashPump"),

    # ── Web ──────────────────────────────────────────────────────────────
    dict(id="sqlmap", category="web", name="SQLMap",
         description="Automated SQL injection detection and exploitation.",
         source="pip", pip_pkg="sqlmap", bin_name="sqlmap",
         url="https://sqlmap.org"),
    dict(id="dirsearch", category="web", name="Dirsearch",
         description="Web path / directory bruteforcer.",
         source="pip", pip_pkg="dirsearch", bin_name="dirsearch", python_module="dirsearch",
         url="https://github.com/maurosoria/dirsearch"),
    dict(id="wfuzz", category="web", name="Wfuzz",
         description="Web fuzzer for parameters, endpoints, payloads.",
         source="pip", pip_pkg="wfuzz", bin_name="wfuzz",
         url="https://github.com/xmendez/wfuzz"),
    dict(id="ffuf", category="web", name="FFUF",
         description="Fast web fuzzer (directories, subdomains, params).",
         source="apt", apt_pkg="ffuf", bin_name="ffuf", os="linux",
         url="https://github.com/ffuf/ffuf",
         install_hint="Windows: scoop install ffuf"),
    dict(id="gobuster", category="web", name="Gobuster",
         description="Directory and DNS subdomain bruteforcer.",
         source="apt", apt_pkg="gobuster", bin_name="gobuster", os="linux",
         url="https://github.com/OJ/gobuster",
         install_hint="Windows: scoop install gobuster"),
    dict(id="nikto", category="web", name="Nikto",
         description="Web server scanner (known CVEs, misconfigs).",
         source="apt", apt_pkg="nikto", bin_name="nikto", os="linux",
         url="https://cirt.net/Nikto2"),
    dict(id="git-dumper", category="web", name="git-dumper",
         description="Dump a .git repository from a misconfigured server.",
         source="pip", pip_pkg="git-dumper", bin_name="git-dumper", python_module="git_dumper",
         url="https://github.com/arthaud/git-dumper"),
    dict(id="arjun", category="web", name="Arjun",
         description="HTTP parameter discovery.",
         source="pip", pip_pkg="arjun", bin_name="arjun", python_module="arjun",
         url="https://github.com/s0md3v/Arjun"),
    dict(id="mitmproxy", category="web", name="mitmproxy",
         description="Intercepting HTTPS proxy for web debugging.",
         source="pip", pip_pkg="mitmproxy", bin_name="mitmproxy",
         url="https://mitmproxy.org"),
    dict(id="burpsuite", category="web", name="Burp Suite",
         description="Web proxy / repeater / intruder for naughty web stuff.",
         source="manual",
         url="https://portswigger.net/burp",
         install_hint="Download Community edition from portswigger.net."),
    dict(id="seclists", category="web", name="SecLists",
         description="Curated wordlists (payloads, usernames, passwords).",
         source="git", git_url="https://github.com/danielmiessler/SecLists",
         url="https://github.com/danielmiessler/SecLists"),
    dict(id="zap", category="web", name="OWASP ZAP",
         description="Automated web app scanner/proxy (like Burp free).",
         source="manual", bin_name="zap.sh", os="posix",
         url="https://www.zaproxy.org",
         install_hint="Download installer from zazproxy.org."),
    dict(id="wpscan", category="web", name="WPScan",
         description="WordPress vulnerability scanner (themes, plugins, users).",
         source="manual", bin_name="wpscan", os="posix",
         url="https://wpscan.com/wordpress-security-scanner",
         install_hint="gem install wpscan"),
    dict(id="searchsploit", category="web", name="searchsploit",
         description="Offline Exploit-DB search for CVEs/exploits.",
         source="apt", apt_pkg="exploitdb", bin_name="searchsploit", os="linux",
         url="https://www.exploit-db.com/searchsploit"),
    dict(id="corsy", category="web", name="Corsy",
         description="Scan for CORS misconfigurations on websites.",
         source="pip", pip_pkg="corsy", bin_name="corsy", python_module="corsy",
         url="https://github.com/s0md3v/Corsy"),
    dict(id="smuggler", category="web", name="Smuggler",
         description="HTTP request smuggling scanner/fuzzer.",
         source="git", git_url="https://github.com/defparam/smuggler",
         setup=["pip", "install", "-r", "requirements.txt"], os="posix",
         url="https://github.com/defparam/smuggler"),
    dict(id="feroxbuster", category="web", name="Feroxbuster",
         description="Fast rust-based content discovery bruteforcer.",
         source="manual", bin_name="feroxbuster", os="linux",
         url="https://github.com/epi052/feroxbuster",
         install_hint="cargo install feroxbuster or download a release binary."),

    # ── Recon ────────────────────────────────────────────────────────────
    dict(id="nmap", category="recon", name="Nmap",
         description="Network/port scanner, service and OS detection.",
         source="apt", apt_pkg="nmap", bin_name="nmap", os="posix",
         url="https://nmap.org",
         install_hint="Windows: scoop install nmap"),
    dict(id="masscan", category="recon", name="Masscan",
         description="ASYNCHRONOUS high-speed port scanner.",
         source="apt", apt_pkg="masscan", bin_name="masscan", os="linux",
         url="https://github.com/robertdavidgraham/masscan"),
    dict(id="netcat", category="recon", name="Netcat (nc)",
         description="Swiss-army TCP/UDP: port checks, reverse shells.",
         source="apt", apt_pkg="netcat-openbsd", bin_name="nc", os="linux",
         url="https://www.openbsd.org/faq/pf/nat.html"),
    dict(id="whois", category="recon", name="whois",
         description="Domain registration lookup.",
         source="apt", apt_pkg="whois", bin_name="whois", os="posix",
         url="https://packages.debian.org/whois"),
    dict(id="dig", category="recon", name="dig (dnsutils)",
         description="DNS query tool for records, zone transfers.",
         source="apt", apt_pkg="dnsutils", bin_name="dig", os="linux",
         url="https://www.isc.org/bind/"),
    dict(id="sublist3r", category="recon", name="Sublist3r",
         description="Enumerate subdomains via OSINT search engines.",
         source="pip", pip_pkg="sublist3r", bin_name="sublist3r", python_module="sublist3r",
         url="https://github.com/aboul3la/Sublist3r"),
    dict(id="theharvester", category="recon", name="theHarvester",
         description="Email / subdomain / host OSINT gathering.",
         source="pip", pip_pkg="theHarvester", bin_name="theHarvester", python_module="theHarvester",
         url="https://github.com/laramies/theHarvester"),
    dict(id="wafw00f", category="recon", name="WAFW00F",
         description="Detect which WAF (CDN/firewall) fronts a site.",
         source="pip", pip_pkg="wafw00f", bin_name="wafw00f", python_module="wafw00f",
         url="https://github.com/EnableSecurity/wafw00f"),
    dict(id="amass", category="recon", name="OWASP Amass",
         description="In-depth subdomain enumeration.",
         source="manual", bin_name="amass", os="linux",
         url="https://github.com/owasp-amass/amass",
         install_hint="GO111MODULE=on go install github.com/owasp-amass/amass/v3/...@master"),
    dict(id="dnsrecon", category="recon", name="DNSRecon",
         description="DNS record enumeration, zone transfer attempts.",
         source="pip", pip_pkg="dnsrecon", bin_name="dnsrecon", python_module="dnsrecon",
         url="https://github.com/darkoperator/dnsrecon"),
    dict(id="massdns", category="recon", name="massdns",
         description="High-performance DNS resolver bruteforcer.",
         source="git", git_url="https://github.com/blechschmidt/massdns",
         setup=["make"], bin_name="massdns", os="linux",
         url="https://github.com/blechschmidt/massdns"),
    dict(id="shodan", category="recon", name="Shodan CLI",
         description="Search internet-exposed hosts/ports via Shodan.",
         source="pip", pip_pkg="shodan", bin_name="shodan", python_module="shodan",
         url="https://cli.shodan.io"),
    dict(id="whatweb", category="recon", name="WhatWeb",
         description="Identify web technologies/stack fingerprinting.",
         source="apt", apt_pkg="whatweb", bin_name="whatweb", os="linux",
         url="https://www.morningstarsecurity.com/research/whatweb"),
    dict(id="mtr", category="recon", name="mtr",
         description="traceroute + ping combined (my-traceroute).",
         source="apt", apt_pkg="mtr-tiny", bin_name="mtr", os="linux",
         url="https://www.bitwizard.nl/mtr/"),

    # ── Stegano ──────────────────────────────────────────────────────────
    dict(id="zsteg", category="stego", name="zsteg",
         description="Detect LSB stego data in PNG/BMP.",
         source="manual", bin_name="zsteg", os="linux",
         url="https://github.com/zed-0xff/zsteg",
         install_hint="gem install zsteg"),
    dict(id="steghide", category="stego", name="steghide",
         description="Hide/extract data in images and audio.",
         source="apt", apt_pkg="steghide", bin_name="steghide", os="posix",
         url="https://steghide.sourceforge.net"),
    dict(id="stegsolve", category="stego", name="Stegsolve",
         description="Java image stego viewer: channels, XOR, planes…",
         source="manual", bin_name="stegsolve",
         url="http://www.caesum.com/handbook/stego.htm",
         install_hint="Download stegsolve.jar and link it into PATH."),
    dict(id="sonic-visualizer", category="stego", name="Sonic Visualiser",
         description="Spectogram / audio visualization for audio stego.",
         source="apt", apt_pkg="sonic-visualiser", bin_name="sonic-visualiser", os="linux",
         url="https://www.sonicvisualiser.org",
         install_hint="Windows: download installer from website."),
    dict(id="stegcracker", category="stego", name="StegCracker",
         description="Bruteforce steghide passwords with a wordlist.",
         source="pip", pip_pkg="stegcracker", bin_name="stegcracker", python_module="stegcracker",
         url="https://github.com/Paradoxis/StegCracker"),
    dict(id="stegdetect", category="stego", name="StegDetect",
         description="Spot LSB stego in JPEGs (outguess, jphide, …).",
         source="apt", apt_pkg="stegdetect", bin_name="stegdetect", os="linux",
         url="https://github.com/abeluck/stegdetect"),
    dict(id="imagemagick", category="stego", name="ImageMagick",
         description="Convert/transform images; strip hidden metadata.",
         source="apt", apt_pkg="imagemagick", bin_name="convert", os="posix",
         url="https://imagemagick.org",
         install_hint="Windows: scoop install imagemagick"),
    dict(id="ffmpeg", category="stego", name="FFmpeg",
         description="Audio/video analysis and processing for media stego.",
         source="apt", apt_pkg="ffmpeg", bin_name="ffmpeg", os="posix",
         url="https://ffmpeg.org",
         install_hint="Windows: scoop install ffmpeg"),

    # ── OSINT ────────────────────────────────────────────────────────────
    dict(id="sherlock", category="osint", name="Sherlock",
         description="Find social-media accounts by username (400+ sites).",
         source="pip", pip_pkg="sherlock_project", bin_name="sherlock", python_module="sherlock_project",
         url="https://github.com/sherlock-project/sherlock"),
    dict(id="metagoofil", category="osint", name="MetaGoofil",
         description="Extract metadata from documents found via search.",
         source="pip", pip_pkg="metagoofil", bin_name="metagoofil",
         url="https://github.com/laramies/metagoofil"),
    dict(id="maigret", category="osint", name="Maigret",
         description="OSINT username search across 3000+ sites.",
         source="pip", pip_pkg="maigret", bin_name="maigret", python_module="maigret",
         url="https://github.com/soxoj/maigret"),
    dict(id="holehe", category="osint", name="Holehe",
         description="Check which sites an email is registered on (OSINT).",
         source="pip", pip_pkg="holehe", bin_name="holehe", python_module="holehe",
         url="https://github.com/megadose/holehe"),
    dict(id="waybackurls", category="osint", name="waybackurls",
         description="Fetch URLs from the Wayback Machine for a domain.",
         source="manual", bin_name="waybackurls", os="linux",
         url="https://github.com/tomnomnom/waybackurls",
         install_hint="go install github.com/tomnomnom/waybackurls@latest"),

    # ── Penetration Testing ──────────────────────────────────────────────
    dict(id="hydra", category="pentes", name="Hydra",
         description="Online password brute-forcer (SSH, RDP, HTTP, …).",
         source="apt", apt_pkg="hydra", bin_name="hydra", os="linux",
         url="https://github.com/vanhauser-thc/thc-hydra",
         install_hint="Windows: use WSL or scoop install hydra"),
    dict(id="ncrack", category="pentes", name="Ncrack",
         description="Fast network authentication cracker (RDP, SSH, HTTP…).",
         source="apt", apt_pkg="ncrack", bin_name="ncrack", os="linux",
         url="https://nmap.org/ncrack/"),
    dict(id="medusa", category="pentes", name="Medusa",
         description="Parallel network login brute-forcer (HTTP, SMB, SSH…).",
         source="apt", apt_pkg="medusa", bin_name="medusa", os="linux",
         url="http://foofus.net/goons/jmk/medusa/medusa.html"),
    dict(id="patator", category="pentes", name="Patator",
         description="Multi-purpose brute-forcing tool (FTP, SSH, HTTP form…).",
         source="git", git_url="https://github.com/lanjelot/patator",
         setup=["python", "-m", "pip", "install", "-r", "requirements.txt"], os="linux",
         url="https://github.com/lanjelot/patator"),
    dict(id="nmap-pentes", category="pentes", name="Nmap (Pentest)",
         description="Network scanner — extended OS/service detection scripts.",
         source="apt", apt_pkg="nmap", bin_name="nmap", os="posix",
         url="https://nmap.org",
         install_hint="Windows: scoop install nmap"),
    dict(id="sublist3r-pentes", category="pentes", name="Sublist3r",
         description="Subdomain enumeration via OSINT search engines.",
         source="pip", pip_pkg="sublist3r", bin_name="sublist3r", python_module="sublist3r",
         url="https://github.com/aboul3la/Sublist3r"),
    dict(id="ffuf-pentes", category="pentes", name="FFUF",
         description="Fast web fuzzer for dirs, subdomains, params.",
         source="apt", apt_pkg="ffuf", bin_name="ffuf", os="linux",
         url="https://github.com/ffuf/ffuf",
         install_hint="Windows: scoop install ffuf"),
    dict(id="gobuster-pentes", category="pentes", name="Gobuster",
         description="Directory and DNS subdomain bruteforcer.",
         source="apt", apt_pkg="gobuster", bin_name="gobuster", os="linux",
         url="https://github.com/OJ/gobuster",
         install_hint="Windows: scoop install gobuster"),
    dict(id="metasploit", category="pentes", name="Metasploit",
         description="Exploit framework (msfconsole, modules, payloads).",
         source="manual", bin_name="msfconsole", os="linux",
         url="https://www.metasploit.com",
         install_hint="apt install metasploit-framework or the nightly installer."),
    dict(id="bettercap", category="pentes", name="Bettercap",
         description="Swiss-army network attack / MITM framework.",
         source="apt", apt_pkg="bettercap", bin_name="bettercap", os="linux",
         url="https://www.bettercap.org"),
    dict(id="responder", category="pentes", name="Responder",
         description="LLMNR/NBT-NS/mDNS poisoner for cred gathering.",
         source="git", git_url="https://github.com/lgandx/Responder", os="linux",
         url="https://github.com/lgandx/Responder"),
    dict(id="john-pentes", category="pentes", name="John the Ripper (Jumbo)",
         description="Offline password cracker for many formats.",
         source="apt", apt_pkg="john", bin_name="john", os="posix",
         url="https://www.openwall.com/john/"),
    dict(id="hashcat-pentes", category="pentes", name="Hashcat",
         description="GPU/CPU accelerated password recovery.",
         source="apt", apt_pkg="hashcat", bin_name="hashcat", os="posix",
         url="https://hashcat.net/hashcat/"),
    dict(id="crackmapexec", category="pentes", name="CrackMapExec",
         description="Network service assessment (SMB, SSH, WinRM, …).",
         source="pip", pip_pkg="crackmapexec", bin_name="crackmapexec", python_module="cme",
         url="https://github.com/byt3bl33d3r/CrackMapExec",
         install_hint="Note: newer versions are packaged as 'netexec'."),
    dict(id="impacket", category="pentes", name="Impacket",
         description="Python network protocols suite (SMB, Kerberos, …).",
         source="pip", pip_pkg="impacket", python_module="impacket",
         url="https://github.com/SecureAuthCorp/impacket"),
    dict(id="enum4linux", category="pentes", name="Enum4Linux",
         description="SMB / NetBIOS information scanner.",
         source="apt", apt_pkg="enum4linux", bin_name="enum4linux", os="linux",
         url="https://github.com/CiscoCXSecurity/enum4linux"),
    dict(id="smbmap", category="pentes", name="SMBMap",
         description="SMB share enumeration and access mapping.",
         source="git", git_url="https://github.com/ShawnDEvans/smbmap", os="posix",
         url="https://github.com/ShawnDEvans/smbmap"),
    dict(id="wpscan-pentes", category="pentes", name="WPScan",
         description="WordPress security scanner (themes, plugins, users).",
         source="manual", bin_name="wpscan", os="posix",
         url="https://wpscan.com/wordpress-security-scanner",
         install_hint="gem install wpscan"),
    dict(id="joomscan", category="pentes", name="JoomScan",
         description="Joomla vulnerability scanner.",
         source="git", git_url="https://github.com/rezasp/joomscan", os="linux",
         url="https://github.com/rezasp/joomscan"),
    dict(id="nikto-pentes", category="pentes", name="Nikto",
         description="Web server scanner for CVEs and misconfigs.",
         source="apt", apt_pkg="nikto", bin_name="nikto", os="linux",
         url="https://cirt.net/Nikto2"),

    # ── Misc ─────────────────────────────────────────────────────────────
    dict(id="jq", category="misc", name="jq",
         description="JSON parser / manipulator for API challenges.",
         source="apt", apt_pkg="jq", bin_name="jq", os="posix",
         url="https://jqlang.github.io/jq/",
         install_hint="Windows: scoop install jq"),
    dict(id="python2", category="misc", name="Python 2",
         description="Legacy runtime for old exploit scripts.",
         source="manual", bin_name="python2", os="posix",
         url="https://www.python.org/downloads/release/python-2718/",
         install_hint="Only needed for ancient tooling; consider a container."),
    dict(id="veles", category="misc", name="Veles",
         description="Hex editor with visual binary data analysis.",
         source="manual",
         url="https://codisec.com/veles/",
         install_hint="Download from codisec.com/veles."),
    dict(id="cyberchef", category="misc", name="CyberChef",
         description="Swiss-army web tool for encodings, hashes, recipes.",
         source="manual",
         url="https://gchq.github.io/CyberChef/",
         install_hint="Use the hosted version or self-host the release build."),
    dict(id="tesseract", category="misc", name="Tesseract OCR",
         description="OCR text from images/QR for document challenges.",
         source="apt", apt_pkg="tesseract-ocr", bin_name="tesseract", os="posix",
         url="https://github.com/tesseract-ocr/tesseract"),
    dict(id="zbar-tools", category="misc", name="zbar-tools",
         description="Read QR/barcodes from images (zbarimg).",
         source="apt", apt_pkg="zbar-tools", bin_name="zbarimg", os="posix",
         url="https://github.com/mchehab/zbar"),
    dict(id="p7zip", category="misc", name="p7zip",
         description="7z archive handling for packed challenge files.",
         source="apt", apt_pkg="p7zip-full", bin_name="7z", os="posix",
         url="https://www.7-zip.org",
         install_hint="Windows: scoop install 7zip"),
]

TOOLS: list[ToolEntry] = [ToolEntry(**d) for d in _RAW]
TOOLS_BY_ID: dict[str, ToolEntry] = {t.id: t for t in TOOLS}

_STATUS_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 30.0


def get_entry(tool_id: str) -> ToolEntry | None:
    return TOOLS_BY_ID.get(tool_id)


def categories() -> list[str]:
    """Category keys in display order, intersected with the catalog."""
    order = list(CATEGORY_LABELS.keys())
    present = {t.category for t in TOOLS}
    return [c for c in order if c in present]


def _find_spec(name: str | None):
    if not name:
        return None
    try:
        return importlib.util.find_spec(name)
    except (ImportError, ValueError, AttributeError):
        return None


def check_status(entry: ToolEntry) -> dict:
    """Determine whether a tool is installed on this host.

    Fast, cache-friendly checks:
      1. executable on PATH  -> kind="bin", path=<location>
      2. importable python module (venv) -> kind="pip"
      3. docker image present -> kind="docker"
    """
    cached = _STATUS_CACHE.get(entry.id)
    now = time.monotonic()
    if cached and now - cached[0] < _CACHE_TTL:
        return cached[1]

    status = {"installed": False, "kind": None, "detail": "", "supported": entry.supported_here}

    if entry.supported_here:
        if entry.source == "git":
            dest = entry._dest()
            if dest.exists():
                status = {"installed": True, "kind": "git",
                          "detail": str(dest), "supported": True}

        if not status["installed"] and entry.bin_name:
            path = shutil.which(entry.bin_name)
            if path:
                status = {"installed": True, "kind": "bin",
                          "detail": path, "supported": True}

        if not status["installed"]:
            mod = entry.python_module or (
                (entry.pip_pkg or "").replace("-", "_").lower() or None
            )
            if _find_spec(mod):
                status = {"installed": True, "kind": "pip",
                          "detail": mod or entry.pip_pkg, "supported": True}

    # docker-image tools: too slow to inspect the daemon here; rely on the
    # presence of the docker CLI so we can offer a pull/remove.
    if not status["installed"] and entry.source == "docker":
        if shutil.which("docker"):
            status["kind"] = "docker"

    if not status["installed"] and not status["kind"] and entry.supported_here:
        if entry.source in ("manual", "git", "docker"):
            status["kind"] = entry.source

    _STATUS_CACHE[entry.id] = (now, status)
    return status


def scan_status() -> list[dict]:
    """Status for every tool: [{entry, status}, ...]."""
    return [{"entry": entry, "status": check_status(entry)} for entry in TOOLS]


def grouped_state() -> list[dict]:
    """Tools grouped by category with status, ready for templates/CLI."""
    groups = []
    for cat in categories():
        items = [
            {
                "entry": entry,
                "status": check_status(entry),
            }
            for entry in TOOLS
            if entry.category == cat
        ]
        groups.append({
            "category": cat,
            "label": CATEGORY_LABELS[cat],
            "tools": items,
            "installed": sum(1 for i in items if i["status"]["installed"]),
        })
    installed_total = sum(g["installed"] for g in groups)
    return groups, {"total": len(TOOLS), "installed": installed_total}


def invalidate_cache():
    _STATUS_CACHE.clear()


async def install_tool(tool_id: str, timeout: int = 600) -> dict:
    """Install a tool from the catalog. Returns {ok, output, error}."""
    entry = get_entry(tool_id)
    if not entry:
        return {"ok": False, "output": "", "error": f"Unknown tool: {tool_id}"}
    if not entry.supported_here:
        return {"ok": False, "output": "",
                "error": f"'{entry.name}' is not supported on this platform ({sys.platform})."}

    lines = []
    result = None

    if entry.source == "pip" and entry.pip_pkg:
        result = await run(sys.executable, "-m", "pip", "install", entry.pip_pkg, timeout=timeout)
    elif entry.source == "apt" and entry.apt_pkg:
        result = await run("sudo", "apt-get", "install", "-y", entry.apt_pkg, timeout=timeout)
    elif entry.source == "git" and entry.git_url:
        dest = entry._dest()
        if dest.exists():
            result = type("R", (), {"returncode": 0, "stdout": f"Already cloned at {dest}", "stderr": ""})()
        else:
            result = await run("git", "clone", "--depth", "1", entry.git_url, str(dest), timeout=timeout)
        if result.returncode == 0 and entry.setup:
            for cmd in entry.setup:
                lines.append(f"$ {' '.join(cmd)}  (in {dest})")
                step = await run(*cmd, timeout=timeout, cwd=str(dest))
                if not step.ok:
                    result = step
                    break
    elif entry.source == "docker" and entry.docker_image:
        result = await run("docker", "pull", entry.docker_image, timeout=timeout)
    else:
        result = type("R", (), {"returncode": -1,
                                "stdout": "", "stderr": entry.install_hint or "Manual install — no automated installer."})()

    output = "\n".join(l for l in [*lines, result.stdout, result.stderr] if l) or "(no output)"
    invalidate_cache()
    return {"ok": result.returncode == 0, "output": output, "error": "" if result.returncode == 0 else output}


async def uninstall_tool(tool_id: str) -> dict:
    """Uninstall a tool from the catalog."""
    entry = get_entry(tool_id)
    if not entry:
        return {"ok": False, "output": "", "error": f"Unknown tool: {tool_id}"}
    if not entry.supported_here:
        return {"ok": False, "output": "",
                "error": f"'{entry.name}' is not supported on this platform."}

    result = None
    if entry.source == "pip" and entry.pip_pkg:
        result = await run(sys.executable, "-m", "pip", "uninstall", "-y", entry.pip_pkg, timeout=120)
    elif entry.source == "apt" and entry.apt_pkg:
        result = await run("sudo", "apt-get", "remove", "-y", entry.apt_pkg, timeout=120)
    elif entry.source == "git":
        dest = entry._dest()
        if dest.exists():
            try:
                shutil.rmtree(dest)
                result = type("R", (), {"returncode": 0, "stdout": f"Removed {dest}", "stderr": ""})()
            except OSError as exc:
                result = type("R", (), {"returncode": -1, "stdout": "", "stderr": str(exc)})()
        else:
            result = type("R", (), {"returncode": -1, "stdout": "", "stderr": "Not installed (no clone dir)."})()
    elif entry.source == "docker" and entry.docker_image:
        result = await run("docker", "rmi", entry.docker_image, timeout=120)
    else:
        result = type("R", (), {"returncode": -1, "stdout": "", "stderr": entry.install_hint or "Manual install — nothing to uninstall."})()

    invalidate_cache()
    return {"ok": result.returncode == 0, "output": result.stdout, "error": result.stderr}