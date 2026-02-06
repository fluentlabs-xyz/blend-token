## BLEND Token

BLEND is an ERC-20 token with gasless approvals and transfers. It supports both EIP-2612 `permit` and EIP-3009 authorizations for x402-style payments, with role-based minting.

### Features

- ERC-20 with configurable `name`/`symbol` at deploy (`decimals = 18`)
- Roles: `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE`
- Capped supply (immutable `CAP`)
- Batch minting and multicall
- Optional initial supply minted at deployment
- EIP-2612 `permit` (gasless approvals)
- EIP-3009 `transferWithAuthorization`, `receiveWithAuthorization`, `cancelAuthorization`
- EIP-1271 support for contract wallet signatures

### Standards

- [EIP-20](https://eips.ethereum.org/EIPS/eip-20): Fungible token interface
- [EIP-2612](https://eips.ethereum.org/EIPS/eip-2612): `permit` approvals by signature
- [EIP-3009](https://eips.ethereum.org/EIPS/eip-3009): Gasless transfers by authorization
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712): Typed structured data signing
- [EIP-1271](https://eips.ethereum.org/EIPS/eip-1271): Contract wallet signature validation

### Security Notes

- `transferWithAuthorization` supports contract recipients via relayers; `receiveWithAuthorization` is payee-bound.
- Use `receiveWithAuthorization` for contract recipients to avoid front-running risk in deposit flows.

### Standards Interactions

Problem we solve: gasless approvals and gasless transfers for EOAs and contract wallets without breaking ERC-20 compatibility.

How the standards coexist:
- EIP-2612 and EIP-3009 share the EIP-712 domain but use different type hashes and nonce/state tracking, so signatures do not collide.
- EIP-2612 updates allowances; EIP-3009 moves tokens directly. They are complementary.
- EIP-3009 supports EIP-1271 contract wallets in this token; OZ ERC20Permit is EOA-only.

Tradeoffs and options:
- For contract deposits, prefer `receiveWithAuthorization` to avoid front-running in wrapper flows.
- If you need permit for contract wallets, add an EIP-1271-aware permit extension or rely on EIP-3009 for gasless UX.
- Alternative approaches: only EIP-2612 (simpler), only EIP-3009 (less familiar), or ERC-4337 account abstraction.

### Quickstart

```shell
forge test
export TOKEN_NAME=BLEND
export TOKEN_SYMBOL=BLEND
export TOKEN_CAP=1000000e18
export TOKEN_INITIAL_SUPPLY=0
export TOKEN_INITIAL_RECIPIENT=0x0000000000000000000000000000000000000000
forge script script/DeployBlendToken.s.sol:DeployBlendToken --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
```

### Foundry

Foundry docs: <https://book.getfoundry.sh/>
