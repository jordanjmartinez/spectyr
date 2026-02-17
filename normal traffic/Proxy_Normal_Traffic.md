# Proxy Normal Traffic Logs - Spectyr Training Data

## Log Source: Proxy (Squid Native Format)
## Traffic Type: Normal/Benign
## Event Count: 20

---

## Schema Reference
| TIME | EVENT TYPE | LOG SOURCE | SOURCE IP | DEST IP | PROTOCOL | MESSAGE | KEY VALUE PAIRS |

**Note:** KEY VALUE PAIRS column is for expanded view only, not displayed in main SIEM table.

---

## Log Entries

### Event 1
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:15:22.341 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.45 |
| DEST IP | 142.250.191.46 |
| PROTOCOL | TCP |
| MESSAGE | `1705313722.341 145 10.0.1.45 TCP_MISS/200 15234 GET https://www.google.com/ - DIRECT/142.250.191.46 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.45, dst_ip=142.250.191.46, url=https://www.google.com/, method=GET, http_status=200, bytes=15234, elapsed_ms=145, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 2
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:15:23.512 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.45 |
| DEST IP | 142.250.191.46 |
| PROTOCOL | TCP |
| MESSAGE | `1705313723.512 23 10.0.1.45 TCP_HIT/200 8421 GET https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png - DIRECT/142.250.191.46 image/png` |
| KEY VALUE PAIRS | `src_ip=10.0.1.45, dst_ip=142.250.191.46, url=https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png, method=GET, http_status=200, bytes=8421, elapsed_ms=23, cache_result=TCP_HIT, hierarchy_code=DIRECT, content_type=image/png, user=-` |

---

### Event 3
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:16:45.128 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.50 |
| DEST IP | 151.101.1.69 |
| PROTOCOL | TCP |
| MESSAGE | `1705313805.128 312 10.0.1.50 TCP_MISS/200 45872 GET https://www.reddit.com/ - DIRECT/151.101.1.69 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.50, dst_ip=151.101.1.69, url=https://www.reddit.com/, method=GET, http_status=200, bytes=45872, elapsed_ms=312, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 4
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:17:02.445 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.45 |
| DEST IP | 52.84.214.93 |
| PROTOCOL | TCP |
| MESSAGE | `1705313822.445 189 10.0.1.45 TCP_MISS/200 23156 GET https://docs.microsoft.com/en-us/windows/ - DIRECT/52.84.214.93 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.45, dst_ip=52.84.214.93, url=https://docs.microsoft.com/en-us/windows/, method=GET, http_status=200, bytes=23156, elapsed_ms=189, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 5
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:18:33.672 |
| EVENT TYPE | HTTP_CONNECT |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.45 |
| DEST IP | 140.82.112.4 |
| PROTOCOL | TCP |
| MESSAGE | `1705313913.672 1245 10.0.1.45 TCP_TUNNEL/200 5678 CONNECT github.com:443 - DIRECT/140.82.112.4 -` |
| KEY VALUE PAIRS | `src_ip=10.0.1.45, dst_ip=140.82.112.4, url=github.com:443, method=CONNECT, http_status=200, bytes=5678, elapsed_ms=1245, cache_result=TCP_TUNNEL, hierarchy_code=DIRECT, content_type=-, user=-, dst_port=443` |

---

### Event 6
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:19:11.234 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.50 |
| DEST IP | 104.244.42.193 |
| PROTOCOL | TCP |
| MESSAGE | `1705313951.234 267 10.0.1.50 TCP_MISS/200 34521 GET https://twitter.com/home - DIRECT/104.244.42.193 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.50, dst_ip=104.244.42.193, url=https://twitter.com/home, method=GET, http_status=200, bytes=34521, elapsed_ms=267, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 7
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:20:45.891 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.45 |
| DEST IP | 13.107.42.14 |
| PROTOCOL | TCP |
| MESSAGE | `1705314045.891 156 10.0.1.45 TCP_MISS/200 18934 GET https://outlook.office365.com/mail/inbox - DIRECT/13.107.42.14 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.45, dst_ip=13.107.42.14, url=https://outlook.office365.com/mail/inbox, method=GET, http_status=200, bytes=18934, elapsed_ms=156, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 8
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:21:12.567 |
| EVENT TYPE | HTTP_POST |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.45 |
| DEST IP | 13.107.42.14 |
| PROTOCOL | TCP |
| MESSAGE | `1705314072.567 423 10.0.1.45 TCP_MISS/200 1245 POST https://outlook.office365.com/api/v2.0/me/sendmail - DIRECT/13.107.42.14 application/json` |
| KEY VALUE PAIRS | `src_ip=10.0.1.45, dst_ip=13.107.42.14, url=https://outlook.office365.com/api/v2.0/me/sendmail, method=POST, http_status=200, bytes=1245, elapsed_ms=423, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=application/json, user=-` |

---

### Event 9
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:22:34.123 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.50 |
| DEST IP | 52.96.166.130 |
| PROTOCOL | TCP |
| MESSAGE | `1705314154.123 89 10.0.1.50 TCP_MISS/200 28456 GET https://teams.microsoft.com/_#/conversations - DIRECT/52.96.166.130 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.50, dst_ip=52.96.166.130, url=https://teams.microsoft.com/_#/conversations, method=GET, http_status=200, bytes=28456, elapsed_ms=89, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 10
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:23:56.789 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.45 |
| DEST IP | 31.13.65.36 |
| PROTOCOL | TCP |
| MESSAGE | `1705314236.789 234 10.0.1.45 TCP_MISS/200 56234 GET https://www.linkedin.com/feed/ - DIRECT/31.13.65.36 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.45, dst_ip=31.13.65.36, url=https://www.linkedin.com/feed/, method=GET, http_status=200, bytes=56234, elapsed_ms=234, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 11
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:25:12.345 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.50 |
| DEST IP | 172.217.14.110 |
| PROTOCOL | TCP |
| MESSAGE | `1705314312.345 178 10.0.1.50 TCP_MISS/200 12567 GET https://drive.google.com/drive/my-drive - DIRECT/172.217.14.110 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.50, dst_ip=172.217.14.110, url=https://drive.google.com/drive/my-drive, method=GET, http_status=200, bytes=12567, elapsed_ms=178, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 12
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:26:45.678 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.45 |
| DEST IP | 23.45.67.89 |
| PROTOCOL | TCP |
| MESSAGE | `1705314405.678 45 10.0.1.45 TCP_HIT/200 34521 GET https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css - DIRECT/23.45.67.89 text/css` |
| KEY VALUE PAIRS | `src_ip=10.0.1.45, dst_ip=23.45.67.89, url=https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css, method=GET, http_status=200, bytes=34521, elapsed_ms=45, cache_result=TCP_HIT, hierarchy_code=DIRECT, content_type=text/css, user=-` |

---

### Event 13
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:27:33.901 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.50 |
| DEST IP | 151.101.65.69 |
| PROTOCOL | TCP |
| MESSAGE | `1705314453.901 198 10.0.1.50 TCP_MISS/200 67234 GET https://stackoverflow.com/questions - DIRECT/151.101.65.69 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.50, dst_ip=151.101.65.69, url=https://stackoverflow.com/questions, method=GET, http_status=200, bytes=67234, elapsed_ms=198, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 14
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:28:12.456 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.45 |
| DEST IP | 54.230.202.113 |
| PROTOCOL | TCP |
| MESSAGE | `1705314492.456 234 10.0.1.45 TCP_MISS/200 45678 GET https://aws.amazon.com/console/ - DIRECT/54.230.202.113 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.45, dst_ip=54.230.202.113, url=https://aws.amazon.com/console/, method=GET, http_status=200, bytes=45678, elapsed_ms=234, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 15
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:29:45.789 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.50 |
| DEST IP | 52.84.150.44 |
| PROTOCOL | TCP |
| MESSAGE | `1705314585.789 156 10.0.1.50 TCP_MISS/200 23456 GET https://zoom.us/j/meetings - DIRECT/52.84.150.44 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.50, dst_ip=52.84.150.44, url=https://zoom.us/j/meetings, method=GET, http_status=200, bytes=23456, elapsed_ms=156, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 16
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:30:22.123 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.45 |
| DEST IP | 104.18.32.7 |
| PROTOCOL | TCP |
| MESSAGE | `1705314622.123 89 10.0.1.45 TCP_HIT/200 12345 GET https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js - DIRECT/104.18.32.7 application/javascript` |
| KEY VALUE PAIRS | `src_ip=10.0.1.45, dst_ip=104.18.32.7, url=https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js, method=GET, http_status=200, bytes=12345, elapsed_ms=89, cache_result=TCP_HIT, hierarchy_code=DIRECT, content_type=application/javascript, user=-` |

---

### Event 17
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:31:45.567 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.50 |
| DEST IP | 185.199.108.154 |
| PROTOCOL | TCP |
| MESSAGE | `1705314705.567 267 10.0.1.50 TCP_MISS/200 34567 GET https://docs.github.com/en/repositories - DIRECT/185.199.108.154 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.50, dst_ip=185.199.108.154, url=https://docs.github.com/en/repositories, method=GET, http_status=200, bytes=34567, elapsed_ms=267, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 18
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:32:33.890 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.45 |
| DEST IP | 216.58.214.206 |
| PROTOCOL | TCP |
| MESSAGE | `1705314753.890 145 10.0.1.45 TCP_MISS/200 89123 GET https://www.youtube.com/ - DIRECT/216.58.214.206 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.45, dst_ip=216.58.214.206, url=https://www.youtube.com/, method=GET, http_status=200, bytes=89123, elapsed_ms=145, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 19
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:33:56.234 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.50 |
| DEST IP | 52.96.166.130 |
| PROTOCOL | TCP |
| MESSAGE | `1705314836.234 312 10.0.1.50 TCP_MISS/200 45678 GET https://onedrive.live.com/ - DIRECT/52.96.166.130 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.50, dst_ip=52.96.166.130, url=https://onedrive.live.com/, method=GET, http_status=200, bytes=45678, elapsed_ms=312, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

### Event 20
| Field | Value |
|-------|-------|
| TIME | 2024-01-15 08:35:12.678 |
| EVENT TYPE | HTTP_GET |
| LOG SOURCE | Proxy |
| SOURCE IP | 10.0.1.45 |
| DEST IP | 192.0.78.24 |
| PROTOCOL | TCP |
| MESSAGE | `1705314912.678 178 10.0.1.45 TCP_MISS/200 23456 GET https://wordpress.com/home - DIRECT/192.0.78.24 text/html` |
| KEY VALUE PAIRS | `src_ip=10.0.1.45, dst_ip=192.0.78.24, url=https://wordpress.com/home, method=GET, http_status=200, bytes=23456, elapsed_ms=178, cache_result=TCP_MISS, hierarchy_code=DIRECT, content_type=text/html, user=-` |

---

## Raw Message Format Reference (Squid Native)

```
timestamp elapsed client_ip cache_result/http_status bytes method URL user hierarchy_code/server_ip content_type
```

**Field Descriptions:**
- **timestamp**: Unix epoch with milliseconds (e.g., 1705313722.341)
- **elapsed**: Response time in milliseconds
- **client_ip**: Source IP address of requesting client
- **cache_result**: TCP_MISS (fetched from origin), TCP_HIT (served from cache), TCP_TUNNEL (SSL passthrough)
- **http_status**: Standard HTTP response code
- **bytes**: Size of response in bytes
- **method**: HTTP method (GET, POST, CONNECT, etc.)
- **URL**: Full requested URL
- **user**: Authenticated username or "-" if no auth
- **hierarchy_code**: How request was fulfilled (DIRECT = straight to origin)
- **server_ip**: IP address of destination server
- **content_type**: MIME type of response

---

## Cache Result Codes Reference

| Code | Description |
|------|-------------|
| TCP_HIT | Object served from local cache |
| TCP_MISS | Object fetched from origin server |
| TCP_REFRESH_HIT | Cache hit after revalidation |
| TCP_REFRESH_MISS | Cache miss after revalidation |
| TCP_TUNNEL | SSL/TLS tunnel (CONNECT method) |
| TCP_DENIED | Request denied by ACL |

---

## Network Topology Reference

| IP Address | Hostname | Role |
|------------|----------|------|
| 10.0.1.1 | PROXY01 | Proxy Server |
| 10.0.1.45 | WS-PC045 | Workstation (jsmith) |
| 10.0.1.50 | WS-PC050 | Workstation |

---

## Traffic Patterns Represented

1. **Web Browsing** - Google, Reddit, YouTube, WordPress
2. **Business Applications** - Office 365, Teams, LinkedIn, Zoom
3. **Development Tools** - GitHub, Stack Overflow, AWS Console
4. **Cloud Storage** - Google Drive, OneDrive
5. **CDN Requests** - Cloudflare, jsDelivr (cache hits)
6. **SSL Tunnels** - CONNECT method for HTTPS

---

## Key Security Indicators (Normal Behavior)

- All traffic to legitimate business/productivity sites
- Standard HTTP methods (GET, POST, CONNECT)
- HTTP 200 status codes (successful requests)
- Reasonable response sizes and timing
- Mix of TCP_HIT (cached) and TCP_MISS (fresh) is normal
- DIRECT hierarchy indicates no parent proxy issues
