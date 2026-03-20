import re


# -----------------------------
# helper: extract request path
# -----------------------------

def extract_path(logline):

    m = re.search(r'"(/[^"]+)"', logline)

    if m:
        return m.group(1)

    return logline


# -----------------------------
# attack detection rules
# -----------------------------

rules = [

# wordpress scanning
{
"name":"wordpress_scan",
"pattern":r"/wp-login|/wp-admin|/xmlrpc.php",
"tool":"wpscan",
"severity":2
},

# wordpress plugin exploit scanning
{
"name":"wordpress_plugin_probe",
"pattern":r"/wp-content/plugins",
"tool":"wpscan",
"severity":3
},

# git repo exposure
{
"name":"git_repo_exposure",
"pattern":r"/\.git",
"tool":"repo_scanner",
"severity":3
},

# env file probe
{
"name":"env_file_probe",
"pattern":r"/\.env",
"tool":"config_harvest",
"severity":3
},

# path traversal
{
"name":"path_traversal",
"pattern":r"\.\./\.\./",
"tool":"generic_scanner",
"severity":4
},

# SQL injection
{
"name":"sql_injection_probe",
"pattern":r"union.*select|or.*1=1|sleep\(|benchmark\(",
"tool":"sqlmap_like",
"severity":4
},

# XSS
{
"name":"xss_probe",
"pattern":r"<script>|%3Cscript%3E|alert\(",
"tool":"generic_scanner",
"severity":3
},

# command injection
{
"name":"command_injection",
"pattern":r";wget|;curl|;bash|/bin/sh",
"tool":"exploit_scanner",
"severity":5
},

# laravel phpunit exploit
{
"name":"laravel_phpunit_rce",
"pattern":r"phpunit.*eval-stdin",
"tool":"nuclei_like",
"severity":5
},

# log4shell
{
"name":"log4shell_probe",
"pattern":r"\$\{jndi:",
"tool":"log4shell_scanner",
"severity":5
},

# admin panel scanning
{
"name":"admin_panel_scan",
"pattern":r"/admin|/dashboard|/cpanel|/phpmyadmin",
"tool":"dir_bruteforce",
"severity":2
},

# backup file probing
{
"name":"backup_file_probe",
"pattern":r"\.bak|\.old|backup\.zip|\.tar\.gz",
"tool":"dir_bruteforce",
"severity":2
},

# webshell attempts
{
"name":"webshell_probe",
"pattern":r"shell\.php|cmd\.php|gptsh\.php|wso\.php|r57\.php|c99\.php",
"tool":"exploit_scanner",
"severity":5
},

# IoT botnet scans
{
"name":"iot_botnet_scan",
"pattern":r"/HNAP1|/boaform|/cgi-bin",
"tool":"mirai_like",
"severity":3
}
]


# -----------------------------
# known scanner user-agents
# -----------------------------

user_agent_tools = [

("sqlmap","sqlmap"),
("nikto","nikto"),
("nuclei","nuclei"),
("wpscan","wpscan"),
("gobuster","gobuster"),
("dirbuster","dirbuster"),
("curl","curl_script"),
("python-requests","python_script"),
("go-http-client","go_scanner")
]


def detect_tool(logline):

    lower = logline.lower()

    for ua,tool in user_agent_tools:

        if ua in lower:
            return tool

    return None


# -----------------------------
# main classification
# -----------------------------

def classify(logline):

    path = extract_path(logline)

    detected_tool = detect_tool(logline)

    for rule in rules:

        if re.search(rule["pattern"], path, re.IGNORECASE):

            return {
                "attack_type":rule["name"],
                "tool": detected_tool if detected_tool else rule["tool"],
                "payload":path,
                "severity":rule["severity"]
            }

    return {
        "attack_type":"unknown",
        "tool": detected_tool if detected_tool else "unknown",
        "payload":path,
        "severity":1
    }
