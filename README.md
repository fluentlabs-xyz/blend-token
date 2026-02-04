## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
- **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```

## Standards Used

[EIP-20 (ERC-20)](https://eips.ethereum.org/EIPS/eip-20) defines the baseline fungible token interface (balances, transfers, allowances). BLEND implements ERC-20 to integrate cleanly with wallets, exchanges, and on-chain protocols.

[EIP-2612](https://eips.ethereum.org/EIPS/eip-2612) adds `permit` approvals via signatures, allowing gasless allowance updates and smoother UX in dApps.

[EIP-3009](https://eips.ethereum.org/EIPS/eip-3009) defines gasless token transfers using authorizations (`transferWithAuthorization`, `receiveWithAuthorization`, `cancelAuthorization`) which BLEND uses for x402-style payments.

[EIP-712](https://eips.ethereum.org/EIPS/eip-712) specifies typed structured data signing; BLEND uses it for both EIP-2612 permits and EIP-3009 authorizations.

[EIP-1271](https://eips.ethereum.org/EIPS/eip-1271) standardizes signature validation for smart-contract wallets; BLEND uses it to accept EIP-3009 authorizations from contract accounts.
