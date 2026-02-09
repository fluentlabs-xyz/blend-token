# BLEND Token

## What is this?

BLEND is the native token of the Fluent ecosystem. It's a standard ERC-20 token with built-in support for gasless transactions — users can approve spending or transfer tokens without holding ETH for gas.

**Key points:**

- Standard ERC-20 with 18 decimals
- Gasless approvals via signed permits (EIP-2612)
- Gasless transfers via signed authorizations (EIP-3009)
- Fixed maximum supply set at deployment
- Upgradeable via UUPS proxy pattern

---

## How to Build & Test

**Prerequisites:**

- [Foundry](https://book.getfoundry.sh/getting-started/installation)

**Commands:**

```bash
forge install          # Install dependencies
forge build            # Compile contracts
forge test             # Run tests
forge test -vvv        # Run tests with verbose output
forge coverage         # Generate coverage report
```

---

## Features

- ERC-20 with configurable `name`/`symbol` at deploy (`decimals = 18`)
- Roles: `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE`, `UPGRADER_ROLE`
- Capped supply (`cap()` view)
- Batch minting and multicall
- Optional initial supply minted at deployment
- EIP-2612 `permit` (gasless approvals)
- EIP-3009 `transferWithAuthorization`, `receiveWithAuthorization`, `cancelAuthorization`
- EIP-1271 support for contract wallet signatures (via EIP-3009)

## Standards

- [EIP-20](https://eips.ethereum.org/EIPS/eip-20): Fungible token interface
- [EIP-2612](https://eips.ethereum.org/EIPS/eip-2612): `permit` approvals by signature
- [EIP-3009](https://eips.ethereum.org/EIPS/eip-3009): Gasless transfers by authorization
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712): Typed structured data signing
- [EIP-1271](https://eips.ethereum.org/EIPS/eip-1271): Contract wallet signature validation

## Security Notes

- `transferWithAuthorization` supports contract recipients via relayers; `receiveWithAuthorization` is payee-bound.
- Use `receiveWithAuthorization` for contract recipients to avoid front-running risk in deposit flows.
- Role-based control: admin/upgrade/minter keys are trusted actors; use multisigs for production.

## Standards Interactions

Problem we solve: gasless approvals and gasless transfers for EOAs and contract wallets without breaking ERC-20 compatibility.

How the standards coexist:

- EIP-2612 and EIP-3009 share the EIP-712 domain but use different type hashes and nonce/state tracking, so signatures do not collide.
- EIP-2612 updates allowances; EIP-3009 moves tokens directly. They are complementary.
- EIP-3009 supports EIP-1271 contract wallets in this token; OZ ERC20Permit is EOA-only.

Tradeoffs and options:

- For contract deposits, prefer `receiveWithAuthorization` to avoid front-running in wrapper flows.
- If you need permit for contract wallets, add an EIP-1271-aware permit extension or rely on EIP-3009 for gasless UX.
- Alternative approaches: only EIP-2612 (simpler), only EIP-3009 (less familiar), or ERC-4337 account abstraction.

## Architecture (Upgradeable)

BLEND uses a UUPS proxy. The proxy holds all state; the implementation holds logic and upgrade authorization.
Initialization must be called via the proxy.

## Upgradeability

BLEND uses the UUPS (Universal Upgradeable Proxy Standard) proxy pattern. The contract can be upgraded by addresses holding `UPGRADER_ROLE`.

**To upgrade:**

```solidity
BlendToken(proxy).upgradeToAndCall(newImplementation, "");
```

**Security considerations:**

- Only `UPGRADER_ROLE` holders can upgrade
- Implementation contract cannot be initialized directly
- Storage layout must be preserved across upgrades (use gaps for new variables)

## Role Management

**Role model:**

- `DEFAULT_ADMIN_ROLE` manages role assignment
- `MINTER_ROLE` can mint
- `UPGRADER_ROLE` can upgrade

**Renouncing minting capability:**

To permanently disable minting:

1. Revoke `MINTER_ROLE` from all addresses
2. Optionally revoke `DEFAULT_ADMIN_ROLE` to make this permanent

```solidity
// As admin, revoke minter role
token.revokeRole(MINTER_ROLE, minterAddress);

// To make permanent (WARNING: irreversible!), renounce admin
token.renounceRole(DEFAULT_ADMIN_ROLE, msg.sender);
```

⚠️ **Warning**: Renouncing `DEFAULT_ADMIN_ROLE` removes role management. If no account retains `UPGRADER_ROLE`, upgrades become impossible.

**Burning capability:**

Anyone can burn their own tokens via `burn`. `burnFrom` uses standard allowances.

## Initialization Parameters

The proxy must be initialized exactly once via:
`initialize(name, symbol, cap, initialSupply, initialRecipient, admin)`

- `name`, `symbol`: ERC-20 metadata
- `cap`: maximum total supply (must be > 0)
- `initialSupply`: minted during initialization (0 allowed)
- `initialRecipient`: required if `initialSupply > 0`
- `admin`: receives `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE`, `UPGRADER_ROLE`

## Deployment

```bash
forge script script/DeployBlendToken.s.sol:DeployBlendToken --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
```

## Foundry

Foundry docs: <https://book.getfoundry.sh/>
