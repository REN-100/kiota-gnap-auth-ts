# Proposal: Kiota GNAP Authentication Provider for TypeScript

**Authors:** Super App Africa Limited (ShujaaPay)  
**Date:** April 2026  
**Status:** Active Development — Workstream 2  
**Funded by:** Interledger Foundation — SDK Grant Program

---

## 1. Executive Summary

This proposal describes a **TypeScript authentication provider for Microsoft Kiota** that implements the GNAP (RFC 9635) authorization protocol. The provider enables automatic SDK generation for GNAP-protected APIs — including Open Payments — by handling grant negotiation, HTTP Message Signatures (RFC 9421), token lifecycle management, and grant continuation.

When combined with the `x-gnap` OpenAPI extension (Workstream 1) and Kiota's code generation engine, this provider eliminates the need for developers to manually implement GNAP authorization flows.

## 2. Problem

Developers building on Open Payments must currently:

1. Read and understand RFC 9635 (GNAP) — 98 pages
2. Read and understand RFC 9421 (HTTP Message Signatures) — 62 pages
3. Implement key pair generation and management (Ed25519 or ECDSA)
4. Build the grant request/response state machine
5. Construct `Signature` and `Signature-Input` headers for every request
6. Handle token rotation, continuation, and revocation
7. Manage the interaction redirect flow for user consent

**This represents weeks of integration work per developer, per language.**

## 3. Solution

### 3.1 Architecture

```
┌──────────────────────────────────────────┐
│  Developer's Application                  │
│                                           │
│  const client = new OpenPaymentsClient(); │
│  const payment = await client             │
│    .incomingPayments                      │
│    .create({ amount: '1000', ...});       │
│                                           │
└───────────────┬──────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────┐
│  Kiota-Generated SDK                      │
│  (from Open Payments OpenAPI + x-gnap)    │
│                                           │
│  Automatically calls auth provider        │
│  before each request                      │
└───────────────┬──────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────┐
│  @shujaapay/kiota-gnap-auth-ts           │
│                                           │
│  ┌─────────────────────────────────┐     │
│  │  GnapAuthenticationProvider     │     │
│  │  ├─ authenticateRequest()       │     │
│  │  ├─ obtainGrant()               │     │
│  │  ├─ continueGrant()             │     │
│  │  └─ revokeGrant()               │     │
│  └─────────────────────────────────┘     │
│  ┌─────────────────────────────────┐     │
│  │  HttpMessageSigner              │     │
│  │  (RFC 9421 implementation)      │     │
│  └─────────────────────────────────┘     │
│  ┌─────────────────────────────────┐     │
│  │  KeyManager                     │     │
│  │  (Ed25519 / ECDSA-P256)         │     │
│  └─────────────────────────────────┘     │
└──────────────────────────────────────────┘
```

### 3.2 Key Components

| Component | Description |
|-----------|-------------|
| `GnapAuthenticationProvider` | Implements Kiota's `AuthenticationProvider` interface. Handles grant negotiation, token caching, and automatic refresh. |
| `HttpMessageSigner` | Signs HTTP requests per RFC 9421. Supports `@method`, `@target-uri`, `@authority`, `content-digest`, and `authorization` derived components. |
| `KeyManager` | Generates and stores Ed25519 and ECDSA-P256 key pairs. Supports PEM, JWK, and raw key formats. |
| `GnapTokenCache` | In-memory + optional persistent token storage with TTL-based expiry and continuation URI tracking. |
| `InteractionHandler` | Manages redirect-based and user-code-based interaction flows for resource owner consent. |

### 3.3 API Surface

```typescript
import { GnapAuthenticationProvider } from '@shujaapay/kiota-gnap-auth-ts';

const auth = new GnapAuthenticationProvider({
  grantEndpoint: 'https://auth.wallet.example.com/',
  clientKey: {
    proof: 'httpsig',
    jwk: myKeyPair.publicKey,
  },
  accessRights: [
    {
      type: 'outgoing-payment',
      actions: ['create', 'read'],
      identifier: 'https://wallet.example.com/alice',
    },
  ],
  signer: myKeyPair.privateKey,
});

// Use with Kiota-generated client
const client = createOpenPaymentsClient(auth);
const payment = await client.outgoingPayments.create({
  walletAddress: 'https://wallet.example.com/alice',
  quoteId: 'https://wallet.example.com/quotes/abc123',
});
```

## 4. Deliverables

| Deliverable | Timeline | Status |
|-------------|----------|--------|
| Core `GnapAuthenticationProvider` class | Month 1-2 | 🔄 In Progress |
| HTTP Message Signatures (RFC 9421) | Month 1 | ✅ Complete (`http-message-signatures-ts`) |
| Token caching and continuation | Month 2-3 | 📋 Planned |
| Interaction handler (redirect + user_code) | Month 3 | 📋 Planned |
| Integration tests with Rafiki testnet | Month 3-4 | 📋 Planned |
| npm package publication | Month 4 | 📋 Planned |
| Documentation and examples | Month 4 | 📋 Planned |

## 5. Dependencies

| Package | Purpose |
|---------|---------|
| `@kiota-abstractions` | Kiota authentication provider interface |
| `@shujaapay/http-message-signatures-ts` | RFC 9421 signing (Workstream 4) |
| `@noble/ed25519` | Ed25519 key operations |
| `jose` | JWK/JWS utilities |

## 6. Testing Strategy

- **Unit tests:** Mock grant server, test token lifecycle, signature generation
- **Integration tests:** Real Rafiki testnet (test.interledger.org)
- **Conformance tests:** Validate against the GNAP test suite (gnap-test-suite.interledger.org)

## 7. Related Workstreams

| # | Workstream | Repository |
|---|-----------|------------|
| 1 | GNAP OpenAPI Security Scheme (`x-gnap`) | `gnap-openapi-security-scheme` |
| **2** | **Kiota GNAP Auth Provider (TypeScript)** | **`kiota-gnap-auth-ts`** |
| 3 | Kiota GNAP Auth Provider (Python) | `kiota-gnap-auth-python` |
| 4 | HTTP Message Signatures (TypeScript) | `http-message-signatures-ts` |

---

**Submitted by:**  
Super App Africa Limited  
ShujaaPay — Global Payments. Local Freedom.  
Interledger Foundation SDK Grant Recipient  
Contact: rensonmumbo@gmail.com
