# Brute Force Dictionary Attack — Level 2 Logs

> **Category:** Brute Force
> **Subcategory:** Dictionary Attack (Password Guessing)
> **Difficulty:** Level 2 (Pattern Recognition)
> **Events:** 5
> **MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing

---

## Event 1 of 5 — Failed Logon

{timestamp_1}
4625Windows Security{src_ip}{dst_ip}An account failed to log on.
timestamp = {timestamp_1}
event_type = 4625
source_type = Windows Security
host = {target_hostname}
src_ip = {src_ip}
src_port = {port_1}
workstation = {src_hostname}
target_user = {target_user}
target_domain = {domain}
logon_type = 3
auth_package = NTLM
logon_process = NtLmSsp
failure_reason = Unknown user name or bad password
status = 0xC000006D
sub_status = 0xC000006A
message = An account failed to log on.

---

## Event 2 of 5 — Failed Logon

{timestamp_2}
4625Windows Security{src_ip}{dst_ip}An account failed to log on.
timestamp = {timestamp_2}
event_type = 4625
source_type = Windows Security
host = {target_hostname}
src_ip = {src_ip}
src_port = {port_2}
workstation = {src_hostname}
target_user = {target_user}
target_domain = {domain}
logon_type = 3
auth_package = NTLM
logon_process = NtLmSsp
failure_reason = Unknown user name or bad password
status = 0xC000006D
sub_status = 0xC000006A
message = An account failed to log on.

---

## Event 3 of 5 — Failed Logon

> Port jumps from {port_2} → {port_3} implying many unseen failed attempts between Event 2 and 3.

{timestamp_3}
4625Windows Security{src_ip}{dst_ip}An account failed to log on.
timestamp = {timestamp_3}
event_type = 4625
source_type = Windows Security
host = {target_hostname}
src_ip = {src_ip}
src_port = {port_3}
workstation = {src_hostname}
target_user = {target_user}
target_domain = {domain}
logon_type = 3
auth_package = NTLM
logon_process = NtLmSsp
failure_reason = Unknown user name or bad password
status = 0xC000006D
sub_status = 0xC000006A
message = An account failed to log on.

---

## Event 4 of 5 — Failed Logon

{timestamp_4}
4625Windows Security{src_ip}{dst_ip}An account failed to log on.
timestamp = {timestamp_4}
event_type = 4625
source_type = Windows Security
host = {target_hostname}
src_ip = {src_ip}
src_port = {port_4}
workstation = {src_hostname}
target_user = {target_user}
target_domain = {domain}
logon_type = 3
auth_package = NTLM
logon_process = NtLmSsp
failure_reason = Unknown user name or bad password
status = 0xC000006D
sub_status = 0xC000006A
message = An account failed to log on.

---

## Event 5 of 5 — Successful Logon

{timestamp_5}
4624Windows Security{src_ip}{dst_ip}An account was successfully logged on.
timestamp = {timestamp_5}
event_type = 4624
source_type = Windows Security
host = {target_hostname}
src_ip = {src_ip}
src_port = {port_5}
workstation = {src_hostname}
target_user = {target_user}
target_domain = {domain}
logon_type = 3
logon_id = {logon_id}
auth_package = NTLM
logon_process = NtLmSsp
logon_guid = {00000000-0000-0000-0000-000000000000}
message = An account was successfully logged on.

---

## Generation Rules

| Variable | Rule |
|----------|------|
| {src_ip} | Same across all 5 events |
| {dst_ip} | Same across all 5 events |
| {src_hostname} | Same across all 5 events |
| {target_hostname} | Same across all 5 events |
| {target_user} | Same across all 5 events |
| {domain} | Same across all 5 events |
| {timestamp_1} → {timestamp_2} | 2-3 second gap |
| {timestamp_2} → {timestamp_3} | 2-3 minute gap (hundreds of attempts happened) |
| {timestamp_3} → {timestamp_4} | 2-3 second gap |
| {timestamp_4} → {timestamp_5} | 2-3 second gap |
| {port_1} → {port_2} | Increment by 1 |
| {port_2} → {port_3} | Jump by 100-200 (implies unseen attempts) |
| {port_3} → {port_4} | Increment by 1 |
| {port_4} → {port_5} | Increment by 1 |
| status | Always 0xC000006D for failures |
| sub_status | Always 0xC000006A for failures |

---

## Expected Classification

**Malicious — Brute Force / Dictionary Attack**
