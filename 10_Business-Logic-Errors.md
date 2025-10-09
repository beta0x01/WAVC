## Introduction
Business Logic Errors are flaws in the design and implementation of an application's workflow. They allow an attacker to use legitimate functionality in an unintended way that results in a negative consequence to the organization. This vulnerability can appear in all features of an application.

## Exploitation Techniques

### Payment & Transaction Abuse

**1. Bypassing Payment Process**
- **Intercept Requests:** During the transaction process, intercept all requests to monitor data exchanged between the client and server. Look for critical parameters like:
    - `Success`: Often indicates the status of the transaction.
    - `Referrer`: May point to the request's origin.
    - `Callback`: Typically used for post-transaction redirection.
- **Manipulate Parameter Values:**
    - Change boolean values, for example from `success=false` to `success=true`, to trick the application into processing a failed transaction as successful.
    - Tamper with delivery charge rates, setting them to negative values or zero to reduce the final amount.
- **Remove Parameters:** Remove critical parameters from the request to see how the system reacts. Some systems might have insecure default behaviors when expected parameters are missing.
- **URL Analysis:** If you encounter a parameter containing a URL (e.g., `example.com/payment/MD5HASH`), copy and open it in a new window to analyze the transaction's outcome and flow.
- **Response Tampering:** Use tools to intercept and modify server responses. Altering the response to simulate a successful transaction can sometimes unlock paid features or complete an order.

**2. Coupon Code Abuse**
- **Reusability:** Apply the same code more than once to check if it can be reused.
- **Race Conditions:** Try to use a unique, single-use coupon code on two different accounts simultaneously to see if the check can be bypassed.
- **Parameter Pollution:** Use Mass Assignment or HTTP Parameter Pollution (HPP) to add multiple coupon codes when the application UI only accepts one.
- **Logic Flaws:** Try adding discount codes to products that are explicitly excluded from discounts by tampering with the request.
- **Input Validation:** Test the coupon field for standard web vulnerabilities like XSS and SQLi.

**3. Currency Arbitrage**
- Pay for a product or service in one currency (e.g., USD) and request a refund in a different, stronger currency (e.g., EUR). Fluctuations in conversion rates may result in a monetary gain.

**4. Refund Feature Abuse**
- **Subscription Abuse:** Purchase a product (especially subscriptions), ask for a refund, and then check if the feature or service remains accessible.
- **Race Conditions:** Send multiple, simultaneous requests for a subscription cancellation to see if multiple refunds can be triggered.

### E-commerce & Shopping Cart Abuse

**1. Cart & Wishlist Manipulation**
- **Negative Quantities:** Add a product with a negative quantity alongside other products with positive quantities to reduce the total price.
- **Exceed Stock:** Add a product in a quantity greater than what is available in stock.
- **Cross-User Manipulation:** Check if moving a product from your wishlist to your cart could allow you to move it to, or delete it from, another user's cart.

### User Interaction & Content Abuse

**1. Review & Rating Manipulation**
- **Privilege Escalation:** Post a review as a "Verified Reviewer" without purchasing the product.
- **Parameter Tampering:** Submit a rating outside the allowed scale (e.g., 0, 6, or negative values instead of 1-5).
- **Rate Limiting:** Check if the same user can post multiple ratings for the same product. This is a prime target for Race Condition attacks.
- **File Uploads:** Test file upload fields for missing restrictions on extensions (`.html`, `.svg`, `.php`).
- **Impersonation:** Attempt to post reviews as another user by tampering with user ID parameters.
- **CSRF:** Check if the review submission functionality is protected by anti-CSRF tokens.

**2. Thread & Comment Functionality**
- **Rate Limiting:** Test for unlimited comments on a single thread.
- **Race Conditions:** If a user is only allowed to comment once, use a race condition to attempt posting multiple comments.
- **Privilege Escalation:** Tamper with parameters to post a comment as a "verified user" or other privileged role.
- **Impersonation:** Try posting comments while appearing as another user.

### General Tampering Techniques

**1. Premium Feature & Subscription Abuse**
- **Forceful Browsing:** Directly browse to URLs or endpoints that are supposed to be restricted to premium accounts.
- **Pay-and-Cancel:** Pay for a premium feature and immediately cancel the subscription. If a refund is issued but the feature remains usable, it's a vulnerability.
- **Boolean Tampering:** Look for true/false values in requests, responses, cookies, or local storage (e.g., `isPremium: false`, `proUser: 0`) and flip them to gain access. Use Burp's Match & Replace rules to automate this across the application.

**2. Parameter Tampering**
- **Manipulate Critical Fields:** Tamper with any parameters related to payment, user identity, or object pricing to manipulate their values.
- **Parameter Pollution & Mass Assignment:** Add unexpected parameters or multiple instances of the same parameter to the request to trigger unintended behavior on the backend.
- **Response Manipulation:** Intercept and modify server responses to bypass client-side controls, such as 2FA or UI restrictions.

**3. Cookie & Session Tampering**
- **Examine Cookies:** Inspect cookies for any data related to payment status, user roles, or premium access.
- **Modify Cookie Values:** Alter cookie values and observe how the application's behavior changes.
- **Session Hijacking:** If session tokens are predictable or exposed, attempt to capture and manipulate them during the payment process to gain insights into session management flaws.