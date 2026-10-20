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
        $p1 = /curl\s+[^|;`\r\n]+\|\s*(sh|bash|zsh)/ ascii nocase
        $p2 = /wget\s+[^|;`\r\n]+\|\s*(sh|bash|zsh)/ ascii nocase
        $p3 = /fetch\s*\([^)]+\)\s*\.\s*then\s*\([^)]*exec/ ascii nocase
    condition:
        any of them
}

rule Credential_And_Secret_Harvesting {
    meta:
        description = "Detects access to sensitive environment credentials or private keys"
        severity = "HIGH"
        category = "credential-theft"
    strings:
        $env = "process.env" ascii
        $k1 = "AWS_SECRET_ACCESS_KEY" ascii
        $k2 = "AWS_ACCESS_KEY_ID" ascii
        $k3 = "NPM_TOKEN" ascii
        $k4 = "GITHUB_TOKEN" ascii
        $k5 = "SLACK_BOT_TOKEN" ascii
        $k6 = "DISCORD_TOKEN" ascii
        $f1 = ".ssh/id_rsa" ascii
        $f2 = ".ssh/id_ed25519" ascii
        $f3 = ".aws/credentials" ascii
        $f4 = "/.npmrc" ascii
        $f5 = "/.env" ascii
        $f6 = "\".env\"" ascii
        $f7 = "'.env'" ascii
    condition:
        ($env and 1 of ($k*)) or 1 of ($f*)
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
