# Recon-X 

## 📋 **PRE-RECON: Setup & Scope**

- [ ] **Read the scope carefully** — Know what's in/out
- [ ] **Note program type** — Public/Private/VDP
- [ ] **Remember wordlists!!** — SecLists, Assetnote, Jhaddix all.txt

---

## 🔍 **PHASE 1: Asset Discovery**

### **1️⃣ ASN & Network Enumeration**

```bash
# ASN by Organization
amass intel -org "<Org Name>" | sort -u > ASN.txt

# CIDR by ASN
whois -h whois.radb.net -- '-i origin <ASN>' | grep -Eo "([0-9.]+){4}/[0-9]+" | sort -u > CIDR.txt

# Domains by ASN
amass intel -asn <ASN> | sort -u > domains_asn.txt

# Domains by CIDR
amass intel -cidr <CIDR> | sort -u > domains_cidr.txt

# Merge all domains
cat domains_*.txt | sort -u > all_domains.txt
```

**WEB Tools to check:**

- https://bgp.he.net/
- https://ipinfo.io/
- https://viewdns.info/

**Notes to take:**

- ASN numbers
- CIDR ranges
- Root domains found

---

### **2️⃣ Reverse WHOIS & DNS Lookup**

```bash
# Reverse DNS
dig +short -x $(dig +short A <Domain>) > reverse_ip.txt

dig +short NS <Domain> | xargs -I{} dig +short -x {} > reverse_ns.txt

dig +short MX <Domain> | awk '{print $2}' | xargs -I{} dig +short -x {} > reverse_mx.txt

# Reverse WHOIS (if you have Whoxy API key)
curl -s "https://api.whoxy.com/?key=<API_KEY>&reverse=whois&email=<Email>" | jq '.search_result.domain_names[]' > whoxy_domains.txt

# Amass WHOIS
amass intel -whois -d <Domain> -o amass_whois.txt

# Merge results
cat whoxy_domains.txt amass_whois.txt | sort -u > whois_domains.txt
```

**Notes to take:**

- Related domains via WHOIS
- Name servers
- Mail servers
- IP relationships

---

### **3️⃣ Subdomain Enumeration**

```bash
# Passive enumeration
amass enum -passive -d <Domain> -o amass_subs.txt

subfinder -d <Domain> -o subfinder_subs.txt

assetfinder --subs-only <Domain> > assetfinder_subs.txt

# Certificate Transparency
python certsh.py -d <Domain> > certsh_subs.txt

# GitHub leaks
./github-subdomains.py -d <Domain> -t <GITHUB_TOKEN> > github_subs.txt

# Merge all subdomains
cat *_subs.txt | sort -u > all_subdomains.txt
```

**Notes to take:**

- Total subdomains found
- Interesting subdomain patterns (dev-, staging-, test-, admin-)

---

### **4️⃣ DNS Resolution & Live Host Detection**

```bash
# Get public DNS resolvers
curl -s https://public-dns.info/nameservers.txt | shuf > resolvers.txt

# Resolve subdomains
massdns -r resolvers.txt -t A -o J all_subdomains.txt | jq 'select(.resp_type=="A") | .query_name' | sort -u > resolved_subs.txt

# HTTP probing
cat resolved_subs.txt | httpx -silent -mc 200,301,302,403 -o live_hosts.txt
```

**Notes to take:**

- Live subdomains count
- HTTP vs HTTPS
- Response codes

---

### **5️⃣ Subdomain Permutation (Advanced)**

```bash
# Generate permutations
altdns -i resolved_subs.txt -o permutations.txt -w words.txt -r -s resolved_permutations.txt
```

**Notes to take:**

- New subdomains discovered via permutation

---

### **6️⃣ Subdomain Takeover Check**

```bash
# Check for takeover
subjack -w resolved_subs.txt -t 100 -timeout 30 -o takeovers.txt -ssl
```

**Notes to take:**

- Dangling CNAMEs
- Unclaimed services (S3, Azure, GitHub Pages, etc.)

---

## 🌐 **PHASE 2: Web Enumeration**

### **1️⃣ Screenshots**

```bash
# EyeWitness
eyewitness --web -f live_hosts.txt --headless --threads 10 -d eyewitness_screens
```

**Notes to take:**

- Interesting admin panels
- Login pages
- Error pages
- Old/deprecated interfaces

---

### **2️⃣ Technology Fingerprinting**

```bash
# Wappalyzer (manual via extension or automated)
python3 wappylyzer.py analyze -u <URL>

# Whatweb
whatweb -i live_hosts.txt -a 3 --log-verbose=whatweb_results.txt

# WAF detection
wafw00f -i live_hosts.txt -o waf_results.txt
```

**Notes to take:**

- Web servers (Nginx, Apache, IIS)
- Frameworks (Laravel, Django, Express, Rails)
- CMS (WordPress, Joomla, Drupal + versions)
- WAF detected (Cloudflare, AWS WAF, Akamai)
- JavaScript libraries and versions

---

### **3️⃣ Port Scanning**

```bash
# Masscan for fast sweep
sudo masscan -p1-65535 <CIDR> --rate=10000 --banners -oX masscan_results.xml

# Nmap for detailed scan
nmap -iL live_ips.txt -p- -sV -sC -oA nmap_results
```

**Notes to take:**

- Open ports (22, 80, 443, 3306, 8080, etc.)
- Service versions
- Banner information

---

### **4️⃣ Content Discovery**

```bash
# Directory bruteforce
gobuster dir -u <URL> -w raft-large-directories.txt -t 50 -o gobuster_dirs.txt

# File bruteforce
gobuster dir -u <URL> -w raft-large-files.txt -t 50 -o gobuster_files.txt

# Check for common files
ffuf -u https://<Domain>/FUZZ -w common-files.txt -mc 200,301,302,403 -o ffuf_files.txt
```

**Notes to take:**

- Admin panels (`/admin`, `/dashboard`, `/cpanel`)
- Backup files (`.bak`, `.old`, `config.php~`)
- API endpoints (`/api/v1`, `/graphql`, `/swagger`)
- Upload directories
- `.git`, `.env` exposure

---

### **5️⃣ Crawling & Spidering**

```bash
# Katana crawling
cat live_hosts.txt | katana -d 5 -jc -silent | tee katana_output.txt

# Extract unique URLs
cat katana_output.txt | sort -u > unique_urls.txt

# Extract JS files
cat katana_output.txt | grep '\.js$' | sort -u > all_js_files.txt

# Extract API endpoints
cat katana_output.txt | grep -Eo '/api/[^"?]+' | sort -u > api_endpoints.txt
```

**Notes to take:**

- Total URLs crawled
- Interesting endpoints
- Hidden parameters

---

### **6️⃣ JavaScript Analysis**

```bash
# Get JS files from live hosts
cat live_hosts.txt | gau | grep '\.js$' | anew all_js.txt

# Probe live JS files
cat all_js.txt | httpx -mc 200 -silent -o live_js.txt

# Extract secrets
cat live_js.txt | nuclei -t credentials-disclosure-all.yaml -o js_secrets.txt

# Extract endpoints
cat live_js.txt | xargs -I{} python linkfinder.py -i {} -o cli | tee linkfinder_output.txt
```

**Notes to take:**

- Hardcoded API keys
- Tokens (JWT, session)
- Internal URLs
- Hidden endpoints
- AWS keys, Google API keys

---

### **7️⃣ Wayback & Archive Data**

```bash
# Wayback URLs
gau <Domain> | tee wayback_urls.txt

# Filter for interesting endpoints
cat wayback_urls.txt | grep -E "admin|config|backup|api|key|token" > interesting_wayback.txt
```

**Notes to take:**

- Old endpoints no longer linked
- Deprecated APIs
- Historical parameters

---

### **8️⃣ Parameter Discovery**

```bash
# Parameter fuzzing
cat unique_urls.txt | grep "=" | unfurl keys | sort -u > parameters.txt

# Arjun for hidden params
arjun -i live_hosts.txt -oT arjun_params.txt
```

**Notes to take:**

- GET/POST parameters
- Hidden parameters discovered

---

### **9️⃣ Google Dorking**

```bash
# Manual or automated
site:<Domain> ext:pdf OR ext:sql OR ext:zip OR ext:env

site:<Domain> inurl:admin OR inurl:login OR inurl:dashboard

site:pastebin.com "<Domain>"

site:github.com "<Domain>" password OR api_key

```

**Notes to take:**

- Exposed files
- Leaked credentials
- GitHub/Pastebin leaks

---

### **🔟 Cloud Storage Enumeration**

```bash
# S3 bucket enumeration
python s3scanner.py --bucket <company-name>

# Google Cloud Storage
gsutil ls -r gs://<bucket-name>
```

**Notes to take:**

- Open S3/Azure/GCP buckets
- Publicly accessible files

---

## 📝 **FINAL CHECKLIST**

- [ ] All subdomains enumerated
- [ ] DNS resolved and live hosts confirmed
- [ ] Screenshots taken
- [ ] Technologies fingerprinted
- [ ] Ports scanned
- [ ] Directories/files bruteforced
- [ ] JS files analyzed for secrets
- [ ] Wayback data mined
- [ ] Parameters discovered
- [ ] Google dorking completed