// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, StdInvariant} from "forge-std/Test.sol";

import {BlendToken} from "../src/BlendToken.sol";
import {IEIP3009} from "../src/interfaces/IEIP3009.sol";

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

contract BlendTokenTest is Test {
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    bytes32 private constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 private constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    bytes32 private constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    uint256 private constant CAP = 1_000_000e18;

    BlendToken private token;

    uint256 private ownerPk = 0xA11CE;
    uint256 private minterPk = 0xB0B;
    uint256 private userPk = 0xCAFE;
    uint256 private spenderPk = 0xD00D;

    address private owner;
    address private minter;
    address private user;
    address private spender;

    function setUp() public {
        owner = vm.addr(ownerPk);
        minter = vm.addr(minterPk);
        user = vm.addr(userPk);
        spender = vm.addr(spenderPk);

        vm.startPrank(owner);
        token = new BlendToken(CAP);
        token.grantRole(token.MINTER_ROLE(), minter);
        vm.stopPrank();
    }

    function testMintRespectsCap() public {
        vm.prank(minter);
        token.mint(user, CAP);
        assertEq(token.totalSupply(), CAP);

        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(BlendToken.CapExceeded.selector, CAP, CAP + 1));
        token.mint(user, 1);
    }

    function testRolePermissions() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user, token.MINTER_ROLE())
        );
        vm.prank(user);
        token.mint(user, 1);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, user, token.PAUSER_ROLE())
        );
        vm.prank(user);
        token.pause();
    }

    function testPauseBehavior() public {
        vm.prank(minter);
        token.mint(user, 10e18);

        vm.prank(owner);
        token.pause();

        vm.expectRevert(Pausable.EnforcedPause.selector);
        vm.prank(user);
        vm.assertFalse(token.transfer(spender, 1e18));

        vm.expectRevert(Pausable.EnforcedPause.selector);
        vm.prank(user);
        token.approve(spender, 1e18);

        uint256 deadline = block.timestamp + 1 days;
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(userPk, user, spender, 1e18, deadline);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        token.permit(user, spender, 1e18, deadline, v, r, s);
    }

    function testCancelAuthorizationWhilePaused() public {
        bytes32 nonce = keccak256("pause-cancel");
        (uint8 v, bytes32 r, bytes32 s) = _signCancelAuth(userPk, user, nonce);

        vm.prank(owner);
        token.pause();

        token.cancelAuthorization(user, nonce, v, r, s);
        assertTrue(token.authorizationState(user, nonce));
    }

    function testPermitHappyPath() public {
        uint256 deadline = block.timestamp + 1 days;
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(userPk, user, spender, 10e18, deadline);

        token.permit(user, spender, 10e18, deadline, v, r, s);
        assertEq(token.allowance(user, spender), 10e18);
    }

    function testPermitInvalidSignature() public {
        uint256 deadline = block.timestamp + 1 days;
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(spenderPk, user, spender, 10e18, deadline);

        vm.expectRevert(abi.encodeWithSelector(ERC20Permit.ERC2612InvalidSigner.selector, vm.addr(spenderPk), user));
        token.permit(user, spender, 10e18, deadline, v, r, s);
    }

    function testPermitExpired() public {
        uint256 deadline = block.timestamp - 1;
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(userPk, user, spender, 10e18, deadline);

        vm.expectRevert(abi.encodeWithSelector(ERC20Permit.ERC2612ExpiredSignature.selector, deadline));
        token.permit(user, spender, 10e18, deadline, v, r, s);
    }

    function testTransferWithAuthorization() public {
        vm.prank(minter);
        token.mint(user, 100e18);

        bytes32 nonce = keccak256("auth-1");
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferAuth(userPk, user, spender, 25e18, validAfter, validBefore, nonce);

        token.transferWithAuthorization(user, spender, 25e18, validAfter, validBefore, nonce, v, r, s);
        assertEq(token.balanceOf(spender), 25e18);
        assertTrue(token.authorizationState(user, nonce));
    }

    function testTransferWithAuthorizationToContractRequiresPayeeCall() public {
        vm.prank(minter);
        token.mint(user, 10e18);

        MockReceiver receiver = new MockReceiver();
        bytes32 nonce = keccak256("auth-contract");
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;

        (uint8 v, bytes32 r, bytes32 s) =
            _signTransferAuth(userPk, user, address(receiver), 1e18, validAfter, validBefore, nonce);

        vm.expectRevert(abi.encodeWithSelector(BlendToken.UnsafeRecipient.selector, address(receiver)));
        token.transferWithAuthorization(user, address(receiver), 1e18, validAfter, validBefore, nonce, v, r, s);
    }

    function testEIP1271Authorization() public {
        Mock1271Wallet wallet = new Mock1271Wallet();

        vm.prank(minter);
        token.mint(address(wallet), 5e18);

        bytes32 nonce = keccak256("auth-1271");
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;

        token.transferWithAuthorization(
            address(wallet), spender, 2e18, validAfter, validBefore, nonce, 0, bytes32(0), bytes32(0)
        );

        assertEq(token.balanceOf(spender), 2e18);
    }

    function testReceiveWithAuthorizationPayeeBinding() public {
        vm.prank(minter);
        token.mint(user, 100e18);

        bytes32 nonce = keccak256("auth-2");
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;

        (uint8 v, bytes32 r, bytes32 s) = _signReceiveAuth(userPk, user, spender, 10e18, validAfter, validBefore, nonce);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(BlendToken.InvalidPayee.selector, user, spender));
        token.receiveWithAuthorization(user, spender, 10e18, validAfter, validBefore, nonce, v, r, s);

        vm.prank(spender);
        token.receiveWithAuthorization(user, spender, 10e18, validAfter, validBefore, nonce, v, r, s);
        assertEq(token.balanceOf(spender), 10e18);
    }

    function testCancelAuthorizationPreventsUse() public {
        vm.prank(minter);
        token.mint(user, 100e18);

        bytes32 nonce = keccak256("auth-3");
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;

        (uint8 vCancel, bytes32 rCancel, bytes32 sCancel) = _signCancelAuth(userPk, user, nonce);
        token.cancelAuthorization(user, nonce, vCancel, rCancel, sCancel);
        assertTrue(token.authorizationState(user, nonce));

        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(userPk, user, spender, 5e18, validAfter, validBefore, nonce);

        vm.expectRevert(abi.encodeWithSelector(BlendToken.AuthorizationAlreadyUsed.selector, user, nonce));
        token.transferWithAuthorization(user, spender, 5e18, validAfter, validBefore, nonce, v, r, s);
    }

    function testReplayProtection() public {
        vm.prank(minter);
        token.mint(user, 100e18);

        bytes32 nonce = keccak256("auth-4");
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;

        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(userPk, user, spender, 5e18, validAfter, validBefore, nonce);

        token.transferWithAuthorization(user, spender, 5e18, validAfter, validBefore, nonce, v, r, s);

        vm.expectRevert(abi.encodeWithSelector(BlendToken.AuthorizationAlreadyUsed.selector, user, nonce));
        token.transferWithAuthorization(user, spender, 5e18, validAfter, validBefore, nonce, v, r, s);
    }

    function testTimeBounds() public {
        // Ensure timestamps are safely above zero to avoid underflow in the test itself.
        vm.warp(1_000);

        vm.prank(minter);
        token.mint(user, 100e18);

        bytes32 nonce = keccak256("auth-5");
        uint256 validAfter = block.timestamp + 100;
        uint256 validBefore = block.timestamp + 1 days;

        (uint8 v, bytes32 r, bytes32 s) = _signTransferAuth(userPk, user, spender, 5e18, validAfter, validBefore, nonce);

        vm.expectRevert(abi.encodeWithSelector(BlendToken.AuthorizationNotYetValid.selector, validAfter));
        token.transferWithAuthorization(user, spender, 5e18, validAfter, validBefore, nonce, v, r, s);

        bytes32 nonce2 = keccak256("auth-6");
        uint256 expiredBefore = block.timestamp - 1;

        (uint8 v2, bytes32 r2, bytes32 s2) =
            _signTransferAuth(userPk, user, spender, 5e18, block.timestamp - 2, expiredBefore, nonce2);

        vm.expectRevert(abi.encodeWithSelector(BlendToken.AuthorizationExpired.selector, expiredBefore));
        token.transferWithAuthorization(user, spender, 5e18, block.timestamp - 2, expiredBefore, nonce2, v2, r2, s2);
    }

    function _signPermit(uint256 signerPk, address owner_, address spender_, uint256 value, uint256 deadline)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 structHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, owner_, spender_, value, token.nonces(owner_), deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        return vm.sign(signerPk, digest);
    }

    function _signTransferAuth(
        uint256 signerPk,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(
            abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        return vm.sign(signerPk, digest);
    }

    function _signReceiveAuth(
        uint256 signerPk,
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 structHash = keccak256(
            abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        return vm.sign(signerPk, digest);
    }

    function _signCancelAuth(uint256 signerPk, address authorizer, bytes32 nonce)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 structHash = keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        return vm.sign(signerPk, digest);
    }
}

contract Mock1271Wallet {
    bytes4 private constant MAGICVALUE = 0x1626ba7e;

    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return MAGICVALUE;
    }
}

contract MockReceiver {}

contract BlendTokenHandler {
    BlendToken public token;
    address public authorizer;
    address public payee;

    bytes32 public transferNonce;
    bytes32 public cancelNonce;
    uint256 public validAfter;
    uint256 public validBefore;
    uint256 public transferValue;

    uint8 public vTransfer;
    bytes32 public rTransfer;
    bytes32 public sTransfer;

    uint8 public vCancel;
    bytes32 public rCancel;
    bytes32 public sCancel;

    bool public reuseSucceeded;

    constructor(BlendToken token_) {
        token = token_;
    }

    function setAuthorizer(address authorizer_) external {
        authorizer = authorizer_;
    }

    function setPayee(address payee_) external {
        payee = payee_;
    }

    function setTransferNonce(bytes32 nonce_) external {
        transferNonce = nonce_;
    }

    function setCancelNonce(bytes32 nonce_) external {
        cancelNonce = nonce_;
    }

    function setTimeBounds(uint256 validAfter_, uint256 validBefore_) external {
        validAfter = validAfter_;
        validBefore = validBefore_;
    }

    function setTransferValue(uint256 value_) external {
        transferValue = value_;
    }

    function setTransferSig(uint8 v, bytes32 r, bytes32 s) external {
        vTransfer = v;
        rTransfer = r;
        sTransfer = s;
    }

    function setCancelSig(uint8 v, bytes32 r, bytes32 s) external {
        vCancel = v;
        rCancel = r;
        sCancel = s;
    }

    function mint(uint256 amount) external {
        (bool ok,) = address(token).call(abi.encodeWithSelector(token.mint.selector, authorizer, amount));
        if (!ok) {
            return;
        }
    }

    function useTransferAuthorization() external {
        bool wasUsed = token.authorizationState(authorizer, transferNonce);
        (bool ok,) = address(token)
            .call(
                abi.encodeWithSelector(
                    IEIP3009.transferWithAuthorization.selector,
                    authorizer,
                    payee,
                    transferValue,
                    validAfter,
                    validBefore,
                    transferNonce,
                    vTransfer,
                    rTransfer,
                    sTransfer
                )
            );
        if (wasUsed && ok) {
            reuseSucceeded = true;
        }
    }

    function cancelAuthorization() external {
        bool wasUsed = token.authorizationState(authorizer, cancelNonce);
        (bool ok,) = address(token)
            .call(
                abi.encodeWithSelector(
                    IEIP3009.cancelAuthorization.selector, authorizer, cancelNonce, vCancel, rCancel, sCancel
                )
            );
        if (wasUsed && ok) {
            reuseSucceeded = true;
        }
    }
}

contract BlendTokenInvariant is StdInvariant, Test {
    BlendToken private token;
    BlendTokenHandler private handler;

    uint256 private authorizerPk = 0xBEEF;
    uint256 private payeePk = 0xF00D;

    struct Sig {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    function setUp() public {
        token = new BlendToken(1_000_000e18);

        address authorizer = vm.addr(authorizerPk);
        address payee = vm.addr(payeePk);

        token.grantRole(token.MINTER_ROLE(), address(this));
        token.mint(authorizer, 1000e18);

        bytes32 transferNonce = keccak256("inv-transfer");
        bytes32 cancelNonce = keccak256("inv-cancel");
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 30 days;
        uint256 transferValue = 1e18;

        Sig memory transferSig =
            _signTransferInvariant(authorizer, payee, transferNonce, validAfter, validBefore, transferValue);

        Sig memory cancelSig = _signCancelInvariant(authorizer, cancelNonce);

        handler = new BlendTokenHandler(token);
        handler.setAuthorizer(authorizer);
        handler.setPayee(payee);
        handler.setTransferNonce(transferNonce);
        handler.setCancelNonce(cancelNonce);
        handler.setTimeBounds(validAfter, validBefore);
        handler.setTransferValue(transferValue);
        handler.setTransferSig(transferSig.v, transferSig.r, transferSig.s);
        handler.setCancelSig(cancelSig.v, cancelSig.r, cancelSig.s);

        token.grantRole(token.MINTER_ROLE(), address(handler));
        targetContract(address(handler));
    }

    function invariant_totalSupplyDoesNotExceedCap() public view {
        assertLe(token.totalSupply(), token.CAP());
    }

    function invariant_authorizationsCannotBeReused() public view {
        assertFalse(handler.reuseSucceeded());
    }

    function _signTransferInvariant(
        address authorizer,
        address payee,
        bytes32 nonce,
        uint256 validAfter,
        uint256 validBefore,
        uint256 value
    ) internal view returns (Sig memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
                ),
                authorizer,
                payee,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizerPk, digest);
        return Sig({v: v, r: r, s: s});
    }

    function _signCancelInvariant(address authorizer, bytes32 nonce) internal view returns (Sig memory) {
        bytes32 structHash = keccak256(
            abi.encode(keccak256("CancelAuthorization(address authorizer,bytes32 nonce)"), authorizer, nonce)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizerPk, digest);
        return Sig({v: v, r: r, s: s});
    }
}
