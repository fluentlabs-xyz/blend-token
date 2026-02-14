// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Vm} from "forge-std/Vm.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BlendToken} from "src/BlendToken.sol";
import {Signatures} from "test/fixtures/Signatures.sol";

contract BlendTokenInvariantTest is StdInvariant, Test {
    BlendToken internal token;
    BlendTokenHandler internal handler;

    uint256 internal constant CAP = 1_000_000e18;
    uint256 internal constant INITIAL_SUPPLY = 100_000e18;

    function setUp() public {
        uint256 deployerPk = 0xA11CE;
        address deployer = vm.addr(deployerPk);

        vm.startPrank(deployer);
        BlendToken implementation = new BlendToken();
        bytes memory initData =
            abi.encodeCall(BlendToken.initialize, ("Fluent", "BLEND", CAP, INITIAL_SUPPLY, deployer, deployer));
        address proxy = address(new ERC1967Proxy(address(implementation), initData));
        token = BlendToken(proxy);
        vm.stopPrank();

        address[] memory actors = new address[](4);
        uint256[] memory keys = new uint256[](4);
        actors[0] = deployer;
        keys[0] = deployerPk;
        actors[1] = vm.addr(0xA1);
        keys[1] = 0xA1;
        actors[2] = vm.addr(0xB2);
        keys[2] = 0xB2;
        actors[3] = vm.addr(0xC3);
        keys[3] = 0xC3;

        handler = new BlendTokenHandler(token, deployer, actors, keys);

        targetContract(address(handler));
        excludeSender(address(0));
    }

    function invariant_totalSupply_capped() public view {
        assertLe(token.totalSupply(), token.cap());
    }

    function invariant_mintedTotal_capped() public view {
        assertLe(token.mintedTotal(), token.cap());
    }

    function invariant_totalSupply_notAboveMinted() public view {
        assertLe(token.totalSupply(), token.mintedTotal());
    }

    function invariant_authorizationState_monotonic() public view {
        (address[] memory authors, bytes32[] memory nonces) = handler.usedAuthorizations();
        for (uint256 i = 0; i < nonces.length; i++) {
            assertTrue(token.authorizationState(authors[i], nonces[i]));
        }
    }

    function invariant_balances_match_handler() public view {
        uint256 count = handler.actorsLength();
        for (uint256 i = 0; i < count; i++) {
            address actor = handler.actors(i);
            assertEq(token.balanceOf(actor), handler.expectedBalance(actor));
        }
    }

    function invariant_allowances_match_handler() public view {
        uint256 count = handler.actorsLength();
        for (uint256 i = 0; i < count; i++) {
            address owner = handler.actors(i);
            for (uint256 j = 0; j < count; j++) {
                address spender = handler.actors(j);
                assertEq(token.allowance(owner, spender), handler.expectedAllowance(owner, spender));
            }
        }
    }
}

contract BlendTokenHandler {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    BlendToken public token;
    address public minter;

    struct AuthData {
        address from;
        address to;
        uint256 amount;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }

    address[] internal actorsList;
    mapping(address => uint256) internal pkOf;
    mapping(address => uint256) internal authNonceCounter;

    mapping(address => uint256) public expectedBalance;
    mapping(address => mapping(address => uint256)) public expectedAllowance;

    address[] internal usedAuthors;
    bytes32[] internal usedNonces;

    constructor(BlendToken _token, address _minter, address[] memory actors_, uint256[] memory keys) {
        require(actors_.length == keys.length, "actors/keys mismatch");
        token = _token;
        minter = _minter;
        actorsList = actors_;

        for (uint256 i = 0; i < actors_.length; i++) {
            pkOf[actors_[i]] = keys[i];
            expectedBalance[actors_[i]] = token.balanceOf(actors_[i]);
        }
    }

    function actors(uint256 index) external view returns (address) {
        return actorsList[index];
    }

    function actorsLength() external view returns (uint256) {
        return actorsList.length;
    }

    function usedAuthorizations() external view returns (address[] memory authors, bytes32[] memory nonces) {
        return (usedAuthors, usedNonces);
    }

    function mint(uint256 toSeed, uint256 rawAmount) external {
        address to = _actor(toSeed);
        uint256 available = token.cap() - token.mintedTotal();
        if (available == 0) return;

        uint256 amount = rawAmount % (available + 1);
        vm.prank(minter);
        token.mint(to, amount);
        expectedBalance[to] += amount;
    }

    function mintBatch(uint256 toSeedA, uint256 toSeedB, uint256 rawAmountA, uint256 rawAmountB) external {
        address toA = _actor(toSeedA);
        address toB = _actor(toSeedB);
        uint256 available = token.cap() - token.mintedTotal();
        if (available == 0) return;

        uint256 amountA = rawAmountA % (available + 1);
        uint256 remaining = available - amountA;
        uint256 amountB = rawAmountB % (remaining + 1);

        address[] memory recipients = new address[](2);
        recipients[0] = toA;
        recipients[1] = toB;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = amountA;
        amounts[1] = amountB;

        vm.prank(minter);
        token.mintBatch(recipients, amounts);

        expectedBalance[toA] += amountA;
        expectedBalance[toB] += amountB;
    }

    function transfer(uint256 fromSeed, uint256 toSeed, uint256 rawAmount) external {
        address from = _actor(fromSeed);
        address to = _actor(toSeed);
        uint256 balance = expectedBalance[from];
        if (balance == 0) return;

        uint256 amount = rawAmount % (balance + 1);
        vm.prank(from);
        token.transfer(to, amount);

        expectedBalance[from] -= amount;
        expectedBalance[to] += amount;
    }

    function approve(uint256 ownerSeed, uint256 spenderSeed, uint256 rawAmount) external {
        address owner = _actor(ownerSeed);
        address spender = _actor(spenderSeed);

        vm.prank(owner);
        token.approve(spender, rawAmount);
        expectedAllowance[owner][spender] = rawAmount;
    }

    function transferFrom(uint256 spenderSeed, uint256 fromSeed, uint256 toSeed, uint256 rawAmount) external {
        address spender = _actor(spenderSeed);
        address from = _actor(fromSeed);
        address to = _actor(toSeed);

        uint256 allowance = expectedAllowance[from][spender];
        uint256 balance = expectedBalance[from];
        uint256 max = balance;
        if (allowance != type(uint256).max && allowance < max) {
            max = allowance;
        }
        if (max == 0) return;

        uint256 amount = rawAmount % (max + 1);
        vm.prank(spender);
        token.transferFrom(from, to, amount);

        expectedBalance[from] -= amount;
        expectedBalance[to] += amount;
        if (allowance != type(uint256).max) {
            expectedAllowance[from][spender] = allowance - amount;
        }
    }

    function permit(uint256 ownerSeed, uint256 spenderSeed, uint256 value, uint256 deadlineDelta) external {
        address owner = _actor(ownerSeed);
        address spender = _actor(spenderSeed);
        uint256 pk = pkOf[owner];
        if (pk == 0) return;

        uint256 deadline = block.timestamp + (deadlineDelta % 1 days) + 1;
        uint256 nonce = token.nonces(owner);

        bytes32 digest = Signatures.permitDigest(token.DOMAIN_SEPARATOR(), owner, spender, value, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);

        vm.prank(spender);
        token.permit(owner, spender, value, deadline, v, r, s);

        expectedAllowance[owner][spender] = value;
    }

    function transferWithAuthorization(uint256 fromSeed, uint256 toSeed, uint256 rawAmount, uint256 validBeforeDelta)
        external
    {
        _ensureTime();
        address from = _actor(fromSeed);
        uint256 balance = expectedBalance[from];
        if (balance == 0) return;

        AuthData memory auth = AuthData({
            from: from,
            to: _actor(toSeed),
            amount: rawAmount % (balance + 1),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + (validBeforeDelta % 1 days) + 1,
            nonce: _nextNonce(from)
        });

        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(auth);
        _callTransferAuth(auth, v, r, s, toSeed);

        expectedBalance[auth.from] -= auth.amount;
        expectedBalance[auth.to] += auth.amount;
        _recordAuthorization(auth.from, auth.nonce);
    }

    function receiveWithAuthorization(uint256 fromSeed, uint256 payeeSeed, uint256 rawAmount, uint256 validBeforeDelta)
        external
    {
        _ensureTime();
        address from = _actor(fromSeed);
        uint256 balance = expectedBalance[from];
        if (balance == 0) return;

        AuthData memory auth = AuthData({
            from: from,
            to: _actor(payeeSeed),
            amount: rawAmount % (balance + 1),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + (validBeforeDelta % 1 days) + 1,
            nonce: _nextNonce(from)
        });

        (uint8 v, bytes32 r, bytes32 s) = _signReceiveAuth(auth);
        _callReceiveAuth(auth, v, r, s);

        expectedBalance[auth.from] -= auth.amount;
        expectedBalance[auth.to] += auth.amount;
        _recordAuthorization(auth.from, auth.nonce);
    }

    function _signTransferAuth(AuthData memory auth) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 digest = Signatures.transferWithAuthorizationDigest(
            token.DOMAIN_SEPARATOR(), auth.from, auth.to, auth.amount, auth.validAfter, auth.validBefore, auth.nonce
        );
        (v, r, s) = vm.sign(pkOf[auth.from], digest);
    }

    function _signReceiveAuth(AuthData memory auth) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 digest = Signatures.receiveWithAuthorizationDigest(
            token.DOMAIN_SEPARATOR(), auth.from, auth.to, auth.amount, auth.validAfter, auth.validBefore, auth.nonce
        );
        (v, r, s) = vm.sign(pkOf[auth.from], digest);
    }

    function _callTransferAuth(AuthData memory auth, uint8 v, bytes32 r, bytes32 s, uint256 toSeed) internal {
        vm.prank(_actor(toSeed + 1));
        token.transferWithAuthorization(
            auth.from, auth.to, auth.amount, auth.validAfter, auth.validBefore, auth.nonce, v, r, s
        );
    }

    function _callReceiveAuth(AuthData memory auth, uint8 v, bytes32 r, bytes32 s) internal {
        vm.prank(auth.to);
        token.receiveWithAuthorization(
            auth.from, auth.to, auth.amount, auth.validAfter, auth.validBefore, auth.nonce, v, r, s
        );
    }

    function cancelAuthorization(uint256 authorizerSeed) external {
        address authorizer = _actor(authorizerSeed);
        bytes32 nonce = _nextNonce(authorizer);

        bytes32 digest = Signatures.cancelAuthorizationDigest(token.DOMAIN_SEPARATOR(), authorizer, nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pkOf[authorizer], digest);

        vm.prank(_actor(authorizerSeed + 1));
        token.cancelAuthorization(authorizer, nonce, v, r, s);

        _recordAuthorization(authorizer, nonce);
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actorsList[seed % actorsList.length];
    }

    function _nextNonce(address authorizer) internal returns (bytes32) {
        uint256 counter = authNonceCounter[authorizer];
        authNonceCounter[authorizer] = counter + 1;
        return keccak256(abi.encode(authorizer, counter));
    }

    function _recordAuthorization(address authorizer, bytes32 nonce) internal {
        usedAuthors.push(authorizer);
        usedNonces.push(nonce);
    }

    function _ensureTime() internal {
        if (block.timestamp == 0) {
            vm.warp(1);
        }
    }
}
