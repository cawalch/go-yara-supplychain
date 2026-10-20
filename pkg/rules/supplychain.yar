/*
 * Supply Chain Core Detection Rules
 * High-speed prefilter signatures targeting malicious dependency behaviors.
 */

rule Suspicious_Piped_Shell {
    meta:
        description = "Detects downloading remote content and piping directly into a shell interpreter"
        severity = "CRITICAL"
        category = "dropper"
    strings:
        $p1 = /curl\s+[^|;`\r\n]+\|\s*(sh|bash|zsh|python)/ ascii nocase
        $p2 = /wget\s+[^|;`\r\n]+\|\s*(sh|bash|zsh|python)/ ascii nocase
        $p3 = /fetch\s*\([^)]+\)\s*\.\s*then\s*\([^)]*exec/ ascii nocase
    condition:
        any of them
}

rule Credential_And_Secret_Harvesting {
    meta:
        description = "Detects access to sensitive environment credentials, private keys, or CMS secrets"
        severity = "HIGH"
        category = "credential-theft"
    strings:
        $env = "process.env" ascii
        $pyenv = "os.environ" ascii
        $k1 = "AWS_SECRET_ACCESS_KEY" ascii
        $k2 = "AWS_ACCESS_KEY_ID" ascii
        $k3 = "NPM_TOKEN" ascii
        $k4 = "GITHUB_TOKEN" ascii
        $k5 = "SLACK_BOT_TOKEN" ascii
        $k6 = "DISCORD_TOKEN" ascii
        $k7 = "PYPI_TOKEN" ascii
        $k8 = "DB_PASSWORD" ascii
        $f1 = ".ssh/id_rsa" ascii
        $f2 = ".ssh/id_ed25519" ascii
        $f3 = ".aws/credentials" ascii
        $f4 = "/.npmrc" ascii
        $f5 = "/.env" ascii
        $f6 = "\".env\"" ascii
        $f7 = "'.env'" ascii
        $f8 = "wp-config.php" ascii
    condition:
        (($env or $pyenv) and 1 of ($k*)) or 1 of ($f*)
}

rule Suspicious_Exfiltration_Endpoint {
    meta:
        description = "Detects outbound connections to public webhook collectors, paste sites, or raw IP addresses"
        severity = "MEDIUM"
        category = "exfiltration"
    strings:
        $w1 = "webhook.site" ascii nocase
        $w2 = "discord.com/api/webhooks" ascii nocase
        $w3 = "pastebin.com/raw" ascii nocase
        $w4 = "pipedream.net" ascii nocase
        $w5 = "requestbin" ascii nocase
        $ip = /(https?:\/\/|['"])[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]{2,5})?['"]?/ ascii
    condition:
        any of them
}

rule Dynamic_Code_Synthesis {
    meta:
        description = "Detects dynamic code evaluation combined with decoding primitives"
        severity = "HIGH"
        category = "obfuscation"
    strings:
        $e1 = "eval(" ascii
        $e2 = "Function(" ascii
        $e3 = "vm.runInThisContext" ascii
        $e4 = "vm.runInNewContext" ascii
        $d1 = "Buffer.from" ascii
        $d2 = "base64" ascii
        $d3 = "atob(" ascii
        $d4 = "fromCharCode" ascii
    condition:
        any of ($e*) and any of ($d*)
}

rule Reverse_Shell_Payload {
    meta:
        description = "Detects reverse shell execution patterns in Node.js"
        severity = "CRITICAL"
        category = "backdoor"
    strings:
        $net = "require('net')" ascii
        $cp = "require('child_process')" ascii
        $sh1 = "/bin/sh" ascii
        $sh2 = "/bin/bash" ascii
        $sh3 = "cmd.exe" ascii
        $spawn = "spawn" ascii
    condition:
        $net and $cp and any of ($sh*) and $spawn
}

rule Python_Suspicious_Install_Hook {
    meta:
        description = "Detects setup.py overriding install/develop command classes to execute arbitrary code"
        severity = "HIGH"
        category = "install-hook"
    strings:
        $c1 = "cmdclass" ascii
        $c2 = "class " ascii
        $i1 = "install" ascii
        $i2 = "develop" ascii
        $i3 = "build_py" ascii
        $s1 = "os.system" ascii
        $s2 = "subprocess" ascii
        $s3 = "exec(" ascii
        $s4 = "urllib" ascii
        $s5 = "requests" ascii
        $s6 = "socket" ascii
    condition:
        $c1 and $c2 and any of ($i*) and any of ($s*)
}

rule Python_Reverse_Shell {
    meta:
        description = "Detects reverse shell execution patterns in Python dependencies"
        severity = "CRITICAL"
        category = "backdoor"
    strings:
        $sock = "socket." ascii
        $conn = ".connect((" ascii
        $dup = "dup2(" ascii
        $sub = "subprocess." ascii
        $pty = "pty.spawn" ascii
        $sh1 = "/bin/sh" ascii
        $sh2 = "/bin/bash" ascii
        $sh3 = "cmd.exe" ascii
    condition:
        $sock and $conn and ($dup or $sub or $pty or any of ($sh*))
}

rule Python_Obfuscated_Execution {
    meta:
        description = "Detects obfuscated code execution via base64 or compression decoding in Python"
        severity = "HIGH"
        category = "obfuscation"
    strings:
        $e1 = "exec(" ascii
        $e2 = "eval(" ascii
        $d1 = "base64.b64decode(" ascii
        $d2 = "b64decode(" ascii
        $d3 = "zlib.decompress(" ascii
        $d4 = "codecs.decode(" ascii
    condition:
        any of ($e*) and any of ($d*)
}

rule PHP_WordPress_SupplyChain_Backdoor {
    meta:
        description = "Detects WordPress supply chain backdoors, rogue admin creation, and core file masquerading"
        severity = "CRITICAL"
        category = "backdoor"
    strings:
        $c2 = "rank1cdn.com" ascii nocase
        $xor_key = "xmmqhn" ascii
        $db1 = "_uf6qdn2hmm" ascii
        $db2 = "t8krdk990phb" ascii
        $db3 = "_np5pvf754c" ascii
        $admin1 = "wpsupport_" ascii
        $admin2 = "@wp-mail.net" ascii
        $cron_tag = "#ms6v46" ascii
        $fake_core = "class-wp-cache-util.php" ascii
        $fpm_sock = "php-fpm" ascii
        $proc_open = "proc_open" ascii
    condition:
        $c2 or
        $xor_key or
        1 of ($db*) or
        ($admin1 and $admin2) or
        $cron_tag or
        $fake_core or
        ($proc_open and $fpm_sock)
}

rule Web_Server_Config_Hijacking {
    meta:
        description = "Detects .htaccess configuration overriding non-executable extensions to execute as PHP"
        severity = "CRITICAL"
        category = "persistence"
    strings:
        $h1 = "application/x-httpd-php" ascii nocase
        $h2 = "SetHandler" ascii nocase
        $h3 = "AddType" ascii nocase
        $h4 = "AddHandler" ascii nocase
        $ext1 = ".cache" ascii nocase
        $ext2 = ".png" ascii nocase
        $ext3 = ".jpg" ascii nocase
        $ext4 = ".ico" ascii nocase
        $ext5 = ".txt" ascii nocase
    condition:
        ($h1 or any of ($h2, $h3, $h4)) and any of ($ext*)
}

rule Python_Pth_AutoExec_Hook {
    meta:
        description = "Detects Python .pth path configuration file abusing interpreter startup auto-execution"
        severity = "CRITICAL"
        category = "dropper"
    strings:
        $p1 = /import\s+(os|subprocess|urllib|requests|sys)/ ascii
        $p2 = /os\.system\(/ ascii
        $p3 = /subprocess\.(Popen|run|call)/ ascii
    condition:
        $p1 and any of ($p2, $p3)
}

rule Bitwise_XOR_Obfuscated_Execution {
    meta:
        description = "Detects bitwise XOR decryption loops paired with dynamic code evaluation"
        severity = "HIGH"
        category = "obfuscation"
    strings:
        $pxor1 = /ord\([^)]+\)\s*\^\s*ord\([^)]+\)/ ascii
        $pxor2 = /\$\w+\[\$\w+\]\s*\^=\s*\$\w+/ ascii
        $py_xor = /\w+\s*\^\s*\w+\[\w+\s*%\s*len\(/ ascii
        $js_xor = /charCodeAt\([^)]+\)\s*\^\s*\w+/ ascii
        $e1 = "eval(" ascii
        $e2 = "assert(" ascii
        $e3 = "create_function(" ascii
        $e4 = "proc_open" ascii
        $e5 = "shell_exec" ascii
    condition:
        any of ($pxor*, $py_xor, $js_xor) and any of ($e*)
}
