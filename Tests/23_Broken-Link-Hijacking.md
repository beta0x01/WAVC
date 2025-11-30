## Overview
Broken Link Hijacking exists whenever a target website links to an external resource, page, or domain that has expired, is no longer in use, or is otherwise available for registration. An attacker can claim this abandoned resource to redirect traffic, host malicious content, or impersonate the target organization, inheriting the trust placed in the original link.

## Exploitation Steps

### 1. Manual Discovery
- Manually browse the target site and click on external links.
- Pay close attention to links pointing to social media accounts (LinkedIn, Twitter, etc.), partner sites, or external media content, as these are often abandoned.

### 2. Automated Scanning
- Use a command-line tool or online scanner to crawl the target application in the background to find broken links efficiently.
- An example output might look like this, indicating a potential takeover target:
  `─BROKEN─ https://www.linkedin.com/company/ACME-inc-/ (HTTP_999)`

### 3. Verification and Takeover
- Once a broken link is identified, visit the service (e.g., LinkedIn, Twitter, GitHub) or domain registrar.
- Check if the page, username, or domain is available for registration.
- If it's available, register it to claim the linked resource and demonstrate the impact.

## Tools

### Command-Line
- **broken-link-checker**
  - A robust Node.js tool for crawling a site.
  - **Basic Scan:**
    ```bash
    # Run a recursive, ordered scan, filtering for only broken links
    blc -rof --filter-level 3 https://example.com/
    ```
  - **Advanced Scan (with exclusions):**
    ```bash
    # Run a recursive, ordered, inclusive scan, excluding common false-positive domains
    blc -rfoi --exclude linkedin.com --exclude youtube.com --filter-level 3 https://example.com/
    ```

### Browser Extensions
- **[Check My Links](https://chrome.google.com/webstore/detail/check-my-links/ojkcdipcgfaekbeaelaapakgnjflfglf/related)**
  - A Google Chrome extension that quickly finds and highlights broken links on an active page.

### Online Scanners
- **[Ahrefs Broken Link Checker](https://ahrefs.com/broken-link-checker)**
- **[Dead Link Checker](https://www.deadlinkchecker.com/)**
- **[Online Broken Link Checker](https://brokenlinkcheck.com/)**

## References
- [Broken Link Hijacking - How expired links can be exploited.](https://edoverflow.com/2017/broken-link-hijacking/)
- [How I was able to takeover the company’s LinkedIn Page](https://medium.com/@bathinivijaysimhareddy/how-i-takeover-the-companys-linkedin-page-790c9ed2b04d)
- [HackerOne Report #1466889](https://hackerone.com/reports/1466889)