## Initial Recon & Enumeration

---

## DNS & UDP Checks

To see if there was something odd with DNS or name resolution:

```bash
dig caddyshack.umbccd.net ANY
```

And that gave me the IP address: 130.85.62.85

Now we’re getting somewhere.

The first step was standard: fire up `nmap` and go full throttle with a complete TCP port scan:

```bash
nmap -sV -Pn -T4 caddyshack.umbccd.net
```

**Result?**
All ports came back filtered or unreachable. Suspicious, but not uncommon for CTFs.

I followed up with basic HTTP tests in case something stealthy was running:

```bash
curl -v http://caddyshack.umbccd.net
curl -Ik https://caddyshack.umbccd.net
whatweb http://caddyshack.umbccd.net
```

**Still nothing.** Timeout after timeout. Both HTTP and HTTPS were filtered.

```bash
sudo nmap -sU --top-ports 50 130.85.62.85
```

Most UDP ports were either closed or open|filtered. No promising leads here either.

---

## Masscan to the Rescue

Sometimes `nmap` misses things due to timing or throttling. So I ran a `masscan` sweep with a slightly aggressive rate:

```bash
sudo masscan 130.85.62.85 -p0-65535 --rate=500 --ping
```

**Open port discovered: 70/tcp**

Now *that* was interesting. Port 70 is old-school — it's the default port for the **Gopher** protocol.

---

## Exploring with Gopher

So I reached for the `gopher` client (yep, still exists!):

```bash
gopher 130.85.62.85
```

Boom — it loaded a classic Gopher-style menu. Clean, minimal, very vintage.

I navigated around the directories until I spotted an entry that looked promising — and there it was:

### Flag: `DawgCTF{60ph3r_15_n07_d34d!}`
