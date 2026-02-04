## BLEND Token

BLEND is an ERC-20 token with gasless approvals and transfers. It supports both EIP-2612 `permit` and EIP-3009 authorizations for x402-style payments, with role-based minting and pausing.

### Features

- ERC-20 with `name = BLEND`, `symbol = BLEND`, `decimals = 18`
- Roles: `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE`, `PAUSER_ROLE`
- Capped supply (immutable `CAP`)
- Pausable transfers and approvals
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

- Use `receiveWithAuthorization` for contract recipients to avoid front-running risk in deposit flows.

### Quickstart

```shell
forge test
forge script script/Deploy.s.sol --rpc-url https://eth-mainnet.public.blastapi.io
```

### Foundry

Foundry docs: <https://book.getfoundry.sh/>
