// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {KnockRegistry} from "../src/KnockRegistry.sol";

interface Vm {
    function etch(address target, bytes calldata code) external;
    function expectRevert(bytes4 selector) external;
    function warp(uint256 time) external;
    function prank(address sender) external;
}

contract KeyStatusFixture {
    function pqcKeyStatus(address account) external pure returns (bool, uint8, bytes memory, bool) {
        return (account != address(5), 1, bytes.concat(bytes20(account), new bytes(2572)), account != address(6));
    }
}

contract VerificationFixture {
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external
        pure
        returns (bool)
    {
        return bytes32(signature[:32]) == keccak256(bytes.concat(pubkey[:20], message));
    }
}

contract KnockRegistryTest {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant DOOR_ID = keccak256("door");
    address private constant OWNER = address(1);
    address private constant DOOR = address(2);
    address private constant APPROVER = address(3);
    address private constant OUTSIDER = address(4);
    uint64 private constant DEADLINE = 200;
    KnockRegistry private registry;

    function setUp() external {
        registry = new KnockRegistry();
        VM.etch(0x0000000000000000000000000000000000000a01, address(new VerificationFixture()).code);
        VM.etch(0x0000000000000000000000000000000000000a02, address(new KeyStatusFixture()).code);
        VM.warp(100);
    }

    function testRegisterAndUpdateByPqAuthorization() external {
        register(OWNER);
        KnockRegistry.Door memory current = registry.door(DOOR_ID);
        require(current.owner == OWNER && current.account == DOOR && current.version == 1);
        require(registry.doorByAccount(DOOR) == DOOR_ID);
        require(registry.nonces(OWNER) == 1 && registry.nonces(DOOR) == 1);
        KnockRegistry.ApprovalPolicy memory next = policy(keccak256("next"));
        bytes memory signature = policySignature(OWNER, next, 2, 1, DEADLINE);
        VM.prank(OUTSIDER);
        registry.updatePolicy(DOOR_ID, 2, next, 1, DEADLINE, signature);
        current = registry.door(DOOR_ID);
        require(current.version == 2 && current.policy.commitment == next.commitment);
        require(registry.nonces(OWNER) == 2);
    }

    function testRegisterRequiresBothProofs() external {
        KnockRegistry.ApprovalPolicy memory initial = policy(keccak256("initial"));
        bytes32 details = keccak256(abi.encode(OWNER, DOOR, uint64(1), initial));
        bytes memory ownerSig = sign(registry.REGISTER_OWNER(), OWNER, details, 0, DEADLINE);
        VM.expectRevert(KnockRegistry.InvalidSignature.selector);
        registry.register(DOOR_ID, OWNER, DOOR, initial, 0, 0, DEADLINE, ownerSig, ownerSig);
        require(registry.nonces(OWNER) == 0 && registry.door(DOOR_ID).version == 0);
    }

    function testClassicalOnlyAndInvalidProofFail() external {
        register(OWNER);
        KnockRegistry.ApprovalPolicy memory next = policy(keccak256("next"));
        VM.prank(OWNER);
        VM.expectRevert(KnockRegistry.InvalidSignature.selector);
        registry.updatePolicy(DOOR_ID, 2, next, 1, DEADLINE, new bytes(65));
        bytes memory outsiderSig = policySignature(OUTSIDER, next, 2, 1, DEADLINE);
        VM.expectRevert(KnockRegistry.InvalidSignature.selector);
        registry.updatePolicy(DOOR_ID, 2, next, 1, DEADLINE, outsiderSig);
        require(registry.door(DOOR_ID).version == 1 && registry.nonces(OWNER) == 1);
    }

    function testMissingOrUnprovenKeyFails() external {
        for (uint160 i = 5; i <= 6; ++i) {
            address owner = address(i);
            bytes memory ownerSignature;
            bytes memory doorSignature;
            KnockRegistry.ApprovalPolicy memory initial = policy(keccak256("initial"));
            bytes32 details = keccak256(abi.encode(owner, DOOR, uint64(1), initial));
            ownerSignature = sign(registry.REGISTER_OWNER(), owner, details, 0, DEADLINE);
            doorSignature = sign(registry.REGISTER_DOOR(), DOOR, details, 0, DEADLINE);
            VM.expectRevert(KnockRegistry.InvalidSignature.selector);
            registry.register(DOOR_ID, owner, DOOR, initial, 0, 0, DEADLINE, ownerSignature, doorSignature);
        }
    }

    function testPolicyTamperingNonceAndDeadlineFail() external {
        register(OWNER);
        KnockRegistry.ApprovalPolicy memory next = policy(keccak256("next"));
        bytes memory signature = policySignature(OWNER, next, 2, 1, DEADLINE);
        next.enabled = false;
        VM.expectRevert(KnockRegistry.InvalidSignature.selector);
        registry.updatePolicy(DOOR_ID, 2, next, 1, DEADLINE, signature);
        next.enabled = true;
        VM.expectRevert(KnockRegistry.InvalidNonce.selector);
        registry.updatePolicy(DOOR_ID, 2, next, 0, DEADLINE, signature);
        VM.warp(DEADLINE);
        VM.expectRevert(KnockRegistry.Expired.selector);
        registry.updatePolicy(DOOR_ID, 2, next, 1, DEADLINE, signature);
        require(registry.door(DOOR_ID).version == 1);
    }

    function testRevocationAndReplay() external {
        register(OWNER);
        bytes32 session = keccak256("session");
        bytes32 details = keccak256(abi.encode(uint64(1), session));
        bytes memory signature = sign(registry.REVOKE(), APPROVER, details, 0, DEADLINE);
        registry.revoke(DOOR_ID, session, 1, APPROVER, 0, DEADLINE, signature);
        require(registry.revoked(DOOR_ID, session));
        VM.expectRevert(KnockRegistry.AlreadyRevoked.selector);
        registry.revoke(DOOR_ID, session, 1, APPROVER, 0, DEADLINE, signature);
        VM.expectRevert(KnockRegistry.InvalidNonce.selector);
        registry.revoke(DOOR_ID, keccak256("another"), 1, APPROVER, 0, DEADLINE, signature);
        VM.expectRevert(KnockRegistry.Unauthorized.selector);
        registry.revoke(DOOR_ID, keccak256("another"), 1, OUTSIDER, 0, DEADLINE, signature);
    }

    function testRemovedApproverCannotRevoke() external {
        register(OWNER);
        KnockRegistry.ApprovalPolicy memory next = policy(keccak256("next"));
        next.approvers[0] = OUTSIDER;
        registry.updatePolicy(DOOR_ID, 2, next, 1, DEADLINE, policySignature(OWNER, next, 2, 1, DEADLINE));
        bytes32 session = keccak256("session");
        bytes32 details = keccak256(abi.encode(uint64(2), session));
        bytes memory signature = sign(registry.REVOKE(), APPROVER, details, 0, DEADLINE);
        VM.expectRevert(KnockRegistry.Unauthorized.selector);
        registry.revoke(DOOR_ID, session, 2, APPROVER, 0, DEADLINE, signature);
        require(!registry.revoked(DOOR_ID, session));
    }

    function testFuzzRevocationIsBoundToOneSession(bytes32 seed) external {
        register(OWNER);
        bytes32 session = bytes32(uint256(seed) | 1);
        bytes32 other = session ^ bytes32(uint256(2));
        bytes32 details = keccak256(abi.encode(uint64(1), session));
        bytes memory signature = sign(registry.REVOKE(), APPROVER, details, 0, DEADLINE);

        VM.expectRevert(KnockRegistry.InvalidSignature.selector);
        registry.revoke(DOOR_ID, other, 1, APPROVER, 0, DEADLINE, signature);
        require(!registry.revoked(DOOR_ID, other) && registry.nonces(APPROVER) == 0);

        registry.revoke(DOOR_ID, session, 1, APPROVER, 0, DEADLINE, signature);
        require(registry.revoked(DOOR_ID, session) && !registry.revoked(DOOR_ID, other));
        VM.expectRevert(KnockRegistry.AlreadyRevoked.selector);
        registry.revoke(DOOR_ID, session, 1, APPROVER, 0, DEADLINE, signature);
        require(registry.nonces(APPROVER) == 1);
    }

    function register(address owner) private {
        KnockRegistry.ApprovalPolicy memory initial = policy(keccak256("initial"));
        bytes32 details = keccak256(abi.encode(owner, DOOR, uint64(1), initial));
        registry.register(
            DOOR_ID,
            owner,
            DOOR,
            initial,
            0,
            0,
            DEADLINE,
            sign(registry.REGISTER_OWNER(), owner, details, 0, DEADLINE),
            sign(registry.REGISTER_DOOR(), DOOR, details, 0, DEADLINE)
        );
    }

    function policy(bytes32 commitment) private pure returns (KnockRegistry.ApprovalPolicy memory) {
        address[] memory approvers = new address[](1);
        approvers[0] = APPROVER;
        return KnockRegistry.ApprovalPolicy(commitment, true, true, approvers);
    }

    function sign(uint8 action, address signer, bytes32 details, uint256 nonce, uint64 deadline)
        private
        view
        returns (bytes memory)
    {
        bytes memory message = registry.authorizationMessage(action, signer, DOOR_ID, details, nonce, deadline);
        return bytes.concat(keccak256(bytes.concat(bytes20(signer), message)), new bytes(4595));
    }

    function policySignature(
        address signer,
        KnockRegistry.ApprovalPolicy memory next,
        uint64 version,
        uint256 nonce,
        uint64 deadline
    ) private view returns (bytes memory) {
        return sign(registry.UPDATE_POLICY(), signer, keccak256(abi.encode(version, next)), nonce, deadline);
    }
}
