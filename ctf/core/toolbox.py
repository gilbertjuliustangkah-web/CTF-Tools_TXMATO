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

    # ── OSINT ────────────────────────────────────────────────────────────
    dict(id="sherlock", category="osint", name="Sherlock",
         description="Find social-media accounts by username (400+ sites).",
         source="pip", pip_pkg="sherlock_project", bin_name="sherlock", python_module="sherlock_project",
         url="https://github.com/sherlock-project/sherlock"),
    dict(id="metagoofil", category="osint", name="MetaGoofil",
         description="Extract metadata from documents found via search.",
         source="pip", pip_pkg="metagoofil", bin_name="metagoofil",
         url="https://github.com/laramies/metagoofil"),

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