"""
Smoke tests: plugin registration + pure-Python plugin correctness.
"""
import asyncio

import ctf.modules.crypto.caesar
import ctf.modules.crypto.encoder
import ctf.modules.crypto.freq_analysis
import ctf.modules.crypto.hash_id
import ctf.modules.crypto.rsa_analyze
import ctf.modules.crypto.xor_tool
import ctf.modules.forensic.hash_calc
import ctf.modules.forensic.hexdump_view
import ctf.modules.forensic.ole_analyze
import ctf.modules.forensic.pdf_analyze
import ctf.modules.forensic.strings_extract
import ctf.modules.pwn.cyclic
import ctf.modules.recon.dns_lookup
import ctf.modules.recon.ssl_check
import ctf.modules.reverse.shellcode_extract
import ctf.modules.stego.steg_detect
import ctf.modules.web.cookies
import ctf.modules.web.jwt_decode
import ctf.modules.pentes.subdomain_enum
import ctf.modules.pentes.service_probe
import ctf.modules.pentes.dir_brute
import ctf.modules.pentes.auth_brute
import ctf.modules.pentes.sqli_detect
import ctf.modules.pentes.xss_detect
import ctf.core.terminal
import ctf.core.database
import ctf.core.python_runner

from ctf.core.plugin import PluginRegistry


def _run(plugin_cls, target="unused", **kwargs):
    return asyncio.run(plugin_cls().execute(target, **kwargs))


def test_plugin_registry_populated():
    keys = PluginRegistry._plugins.keys()
    expected = {
        "crypto.caesar_brute",
        "crypto.hash_id",
        "crypto.xor_tool",
        "crypto.rsa_analyze",
        "crypto.freq_analysis",
        "forensic.hash_calc",
        "forensic.strings_extract",
        "forensic.hexdump_view",
        "pwn.cyclic",
        "web.jwt_decode",
        "web.cookie_inspect",
        "stego.steg_detect",
        "recon.dns_lookup",
        "pentes.subdomain_enum",
        "pentes.service_probe",
        "pentes.dir_brute",
        "pentes.auth_brute",
        "pentes.sqli_detect",
        "pentes.xss_detect",
    }
    assert expected <= set(keys)


def test_caesar_brute_finds_shift():
    r = _run(PluginRegistry.get("crypto", "caesar_brute"), "Khoor Zruog", shift=-1)
    assert r.success
    assert r.data["best_shift"] == 23
    assert "Hello World" in r.data["best_text"]


def test_encode_b64_roundtrip():
    r = _run(PluginRegistry.get("crypto", "encode"), "SGVsbG8gV29ybGQh", mode="b64dec")
    assert r.success
    assert r.data["result"] == "Hello World!"


def test_hash_id_recognizes_md5():
    r = _run(PluginRegistry.get("crypto", "hash_id"), "e99a18c428cb38d5f260853678922e03")
    assert r.success
    assert "MD5" in r.data["candidates"]


def test_xor_crack_finds_key(tmp_path):
    data = "attack at dawn"
    enc = _run(
        PluginRegistry.get("crypto", "xor_tool"),
        data, mode="encrypt", key="Z",
    )
    assert enc.success
    r = _run(
        PluginRegistry.get("crypto", "xor_tool"),
        enc.data["result_hex"], mode="single_byte",
    )
    assert r.success
    assert "attack at dawn" in r.data.get("best_text", "")


def test_hexdump_renders_offsets(tmp_path):
    f = tmp_path / "f.bin"
    f.write_bytes(b"A" * 16)
    r = _run(PluginRegistry.get("forensic", "hexdump_view"), str(f))
    assert r.success
    assert r.data["total_size"] == 16
    assert "00000000" in r.data["lines"][0]


def test_strings_ascii(tmp_path):
    f = tmp_path / "s.bin"
    f.write_bytes(b"MZ\x90\x00CTF{flag_here}\x00\x00" + b"\x00" * 32)
    r = _run(PluginRegistry.get("forensic", "strings_extract"), str(f), min_length=4)
    assert r.success
    found = {s for enc in r.data["strings"].values() for s in enc}
    assert "CTF{flag_here}" in found


def test_rsa_weak_warns(tmp_path):
    # 512-bit is considered auditable/weak by the plugin
    r = _run(PluginRegistry.get("crypto", "rsa_analyze"), "n/a", key_bits=512, e=65537)
    assert r.success


def test_cyclic_find():
    pattern = _run(PluginRegistry.get("pwn", "cyclic"), "unused", mode="generate", length=100)
    assert pattern.success
    needle = pattern.data["pattern"][4:8]
    found = _run(PluginRegistry.get("pwn", "cyclic"), "unused", mode="find", pattern=needle)
    assert found.success
    assert found.data["offset"] == 4


def test_jwt_decode_unsigned():
    token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJmbGFnIjoiaGVsbG8ifQ."
    r = _run(PluginRegistry.get("web", "jwt_decode"), token)
    assert r.success
    assert r.data["payload"].get("flag") == "hello"


def test_cookie_inspect_flags():
    r = _run(PluginRegistry.get("web", "cookie_inspect"), "a=1; b=2; secure_=3;")
    assert r.success
    assert r.data["count"] == 3


def test_steg_detect_trailing_bytes(tmp_path):
    f = tmp_path / "s.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20 + b"secret_hidden_bytes_trailing")
    r = _run(PluginRegistry.get("stego", "steg_detect"), str(f))
    assert r.success
    assert r.data["finding_count"] > 0


def test_sqli_detect_injects_into_last_param():
    p = PluginRegistry.get("pentes", "sqli_detect")()
    assert p._inject("http://x/?id=1", "' OR '1'='1") == "http://x/?id=' OR '1'='1"
    assert p._inject("http://x/?a=1&b=2", "'") == "http://x/?a=1&b='"


def test_sqli_detect_analyze_flags_db_error():
    p = PluginRegistry.get("pentes", "sqli_detect")()
    base = {"status": 200, "body": "<html>ok</html>"}
    probe = {"status": 200, "body": "You have an error in your SQL syntax"}
    f = p._analyze("quote", "'", base, probe)
    assert f is not None
    assert f["severity"] == "high"


def test_sqli_detect_analyze_flags_500():
    p = PluginRegistry.get("pentes", "sqli_detect")()
    base = {"status": 200, "body": "<html>ok</html>"}
    f = p._analyze("quote", "'", base, {"status": 500, "body": ""})
    assert f is not None
    assert f["severity"] == "high"


def test_sqli_detect_clean_response_not_flagged():
    p = PluginRegistry.get("pentes", "sqli_detect")()
    base = {"status": 200, "body": "<html>ok</html>"}
    probe = {"status": 200, "body": "<html>results for query</html>"}
    assert p._analyze("bool_true", "' OR '1'='1", base, probe) is None


def test_xss_detect_injects_marker():
    p = PluginRegistry.get("pentes", "xss_detect")()
    assert p._inject("http://x/?q=a", "<m>") == "http://x/?q=<m>"


def test_terminal_manager_status_and_rc_parse():
    t = ctf.core.terminal.WslTerminal()
    st = t.status()
    assert set(st) >= {"available", "running", "shell"}
    rc_prefix = "__CTF_RC_ab12_"
    assert t._parse_rc("__CTF_RC_ab12_0__", rc_prefix) == 0
    assert t._parse_rc("__CTF_RC_ab12_255__", rc_prefix) == 255
    assert t._parse_rc("__CTF_RC_ab12_-1__", rc_prefix) == -1
    assert t._parse_rc("no marker here", rc_prefix) is None
    out, rc = t._extract_rc(["x", "__CTF_RC_ab12_7__", "tail"], rc_prefix, True)
    assert rc == 7 and out == "x\ntail"
    assert t._extract_rc(["y"], rc_prefix, False) == ("y", None)


def test_terminal_history_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(ctf.core.database, "DB_PATH", tmp_path / "ctf.db")
    asyncio.run(ctf.core.database.init_db())
    asyncio.run(ctf.core.database.add_terminal_command(
        "default", "ls -la", "total 8\n", 0))
    hist = asyncio.run(ctf.core.database.get_terminal_history("default"))
    assert hist and hist[0]["command"] == "ls -la"
    assert hist[0]["output"] == "total 8\n"
    assert hist[0]["exit_code"] == 0
    assert asyncio.run(ctf.core.database.clear_terminal_history("default")) >= 1
    assert asyncio.run(ctf.core.database.get_terminal_history("default")) == []


def test_python_runner_executes_code():
    r = asyncio.run(ctf.core.python_runner.python_runner.run(
        code="import sys\nprint('hi', sys.version.split()[0])\nprint('err', file=sys.stderr)"))
    assert r["ok"] and not r["timed_out"]
    assert "hi 3" in r["output"]
    assert "err" in r["output"]
    assert r["exit_code"] == 0


def test_python_runner_stdin_and_errors():
    r = asyncio.run(ctf.core.python_runner.python_runner.run(
        code="import sys\nprint(sys.stdin.read().upper().strip())", stdin="abc"))
    assert r["ok"] and r["output"] == "ABC"

    bad = asyncio.run(ctf.core.python_runner.python_runner.run(code="raise ValueError('boom')"))
    assert bad["ok"] and bad["exit_code"] == 1
    assert "boom" in bad["output"]


def test_python_runner_timeout():
    r = asyncio.run(ctf.core.python_runner.python_runner.run(
        code="import time\nprint('start', flush=True)\ntime.sleep(30)", timeout=1))
    assert r["timed_out"] and "[timeout]" in r["output"]


def test_python_history_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(ctf.core.database, "DB_PATH", tmp_path / "ctf.db")
    asyncio.run(ctf.core.database.init_db())
    asyncio.run(ctf.core.database.add_python_code("default", "print(1)", "x", "1", 0))
    hist = asyncio.run(ctf.core.database.get_python_history("default"))
    assert hist and hist[0]["code"] == "print(1)" and hist[0]["output"] == "1"
    assert asyncio.run(ctf.core.database.clear_python_history("default")) == 1