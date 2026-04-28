# Kiota GNAP Authentication Provider for TypeScript

> A Kiota-compatible authentication provider implementing GNAP (RFC 9635) for automated Open Payments SDK generation in TypeScript/Node.js.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![RFC 9635](https://img.shields.io/badge/RFC-9635-orange.svg)](https://www.rfc-editor.org/rfc/rfc9635)
[![Kiota](https://img.shields.io/badge/Kiota-compatible-blue.svg)](https://learn.microsoft.com/en-us/openapi/kiota/)

## Overview

This package implements a [Kiota](https://learn.microsoft.com/en-us/openapi/kiota/) `AuthenticationProvider` that handles the complete GNAP authorization lifecycle for Open Payments APIs. When used with Kiota-generated SDKs, it enables **zero-configuration authentication** - developers get working GNAP auth out of the box.

## Features

- **Full GNAP lifecycle** - Grant requests, token acquisition, continuation, rotation, and revocation
- **Kiota-native** - Implements `AuthenticationProvider` and `AccessTokenProvider` interfaces
- **HTTP Message Signatures** - Automatic RFC 9421 request signing via `@shujaapay/http-message-signatures`
- **Token management** - In-memory token store with automatic refresh
- **Key proof support** - Ed25519, ECDSA-P256 key proofs for GNAP
- **Open Payments optimized** - Pre-configured for incoming/outgoing payments and quotes

## Installation

```bash
npm install @shujaapay/kiota-gnap-auth-ts @shujaapay/http-message-signatures
```

## Quick Start

```typescript
import { GnapAuthenticationProvider } from '@shujaapay/kiota-gnap-auth-ts';
import { createGnapSigner } from '@shujaapay/http-message-signatures';

// 1. Create the GNAP auth provider
const authProvider = new GnapAuthenticationProvider({
  grantEndpoint: 'https://auth.wallet.example/',
  clientKey: {
    keyId: 'my-client-key',
    privateKey: myEd25519PrivateKey,
    algorithm: 'ed25519',
    proof: 'httpsig',
  },
  accessRights: [
    { type: 'incoming-payment', actions: ['create', 'read', 'list'] },
    { type: 'outgoing-payment', actions: ['create', 'read', 'list'] },
    { type: 'quote', actions: ['create', 'read'] },
  ],
});

// 2. Use with Kiota-generated client
import { OpenPaymentsClient } from './generated/openPaymentsClient';
import { FetchRequestAdapter } from '@microsoft/kiota-http-fetchlibrary';

const adapter = new FetchRequestAdapter(authProvider);
const client = new OpenPaymentsClient(adapter);

// 3. Make authenticated API calls - GNAP auth is automatic
const payments = await client.incomingPayments.get();
```

## Architecture

```
                    Kiota SDK
                       |
                       v
        +-----------------------------+
        | GnapAuthenticationProvider   |
        |  - authenticateRequest()     |
        |  - getAuthorizationToken()   |
        +-----------------------------+
                       |
          +------------+------------+
          |                         |
          v                         v
  +----------------+    +--------------------+
  | GnapGrantManager|    | HttpSignatureSigner|
  |  - requestGrant |    |  - signRequest     |
  |  - continueGrant|    |  - RFC 9421        |
  |  - rotateToken  |    +--------------------+
  +----------------+          (from @shujaapay/
          |               http-message-signatures)
          v
  +----------------+
  | TokenStore      |
  |  - get/set/clear|
  |  - auto-refresh |
  +----------------+
```

## API Reference

### `GnapAuthenticationProvider`

Main entry point implementing Kiota's `AuthenticationProvider` interface.

```typescript
const provider = new GnapAuthenticationProvider(options: GnapAuthOptions);
```

#### Options

| Parameter | Type | Required | Description |
|---|---|---|---|
| `grantEndpoint` | `string` | Yes | GNAP authorization server URL |
| `clientKey` | `ClientKeyConfig` | Yes | Client key for GNAP proofs |
| `accessRights` | `AccessRight[]` | Yes | Resources to request access to |
| `interaction` | `InteractionConfig` | No | Interaction mode (redirect/user_code) |
| `tokenStore` | `TokenStore` | No | Custom token storage (default: in-memory) |

### `GnapGrantManager`

Manages the GNAP grant lifecycle.

```typescript
const manager = new GnapGrantManager(grantEndpoint, clientKey);

// Request a new grant
const grant = await manager.requestGrant(accessRights, interaction);

// Continue a pending grant
const continued = await manager.continueGrant(continueUri, continueToken, interactRef);

// Rotate an access token
const newToken = await manager.rotateToken(tokenManagementUri, token);

// Revoke an access token
await manager.revokeToken(tokenManagementUri, token);
```

## Project Structure

```
src/
  index.ts                        # Public exports
  gnap-auth-provider.ts           # Kiota AuthenticationProvider implementation
  gnap-access-token-provider.ts   # Kiota AccessTokenProvider implementation
  gnap-grant-manager.ts           # GNAP grant lifecycle management
  token-store.ts                  # Token storage and auto-refresh
  types.ts                        # TypeScript interfaces
tests/
  gnap-auth-provider.test.ts
  gnap-grant-manager.test.ts
  token-store.test.ts
  fixtures/
    mock-grant-server.ts          # Mock GNAP authorization server for testing
```

## Relationship to ShujaaPay GNAP Stack

| Repo | Workstream | Role |
|---|---|---|
| [gnap-openapi-security-scheme](https://github.com/REN-100/gnap-openapi-security-scheme) | WS1 | Defines the x-gnap metadata this provider consumes |
| **This repo** | **WS2** | **Kiota TypeScript GNAP auth provider** |
| [kiota-gnap-auth-python](https://github.com/REN-100/kiota-gnap-auth-python) | WS3 | Python equivalent of this provider |
| [http-message-signatures-ts](https://github.com/REN-100/http-message-signatures-ts) | WS4 | Signing library this provider depends on |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE).
