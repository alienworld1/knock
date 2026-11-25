// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

interface IPqcKeys {
    function pqcKeyStatus(address account)
        external
        view
        returns (bool registered, uint8 algorithmId, bytes memory publicKey, bool possessionProven);
}

interface IPqcVerify {
    function pqcVerify(bytes calldata publicKey, bytes calldata signature, bytes calldata message)
        external
        view
        returns (bool);
}

contract KnockRegistry {
    uint8 public constant REGISTER_OWNER = 1;
    uint8 public constant REGISTER_DOOR = 2;
    uint8 public constant UPDATE_POLICY = 3;
    uint8 public constant REVOKE = 4;

    bytes32 private constant DOMAIN = keccak256("knock-registry-v1");
    address private constant PQC_KEYS = 0x0000000000000000000000000000000000000a02;
    address private constant PQC_VERIFY = 0x0000000000000000000000000000000000000a01;
    uint8 private constant ML_DSA_87 = 1;

    struct ApprovalPolicy {
        bytes32 commitment;
        bool enabled;
        bool approversCanRevoke;
        address[] approvers;
    }

    struct Door {
        address owner;
        address account;
        uint64 version;
        ApprovalPolicy policy;
    }

    mapping(address => uint256) public nonces;
    mapping(address => bytes32) public doorByAccount;
    mapping(bytes32 => Door) private doors;
    mapping(bytes32 => mapping(bytes32 => bool)) public revoked;

    error InvalidDoor();
    error InvalidPolicy();
    error Unauthorized();
    error InvalidNonce();
    error Expired();
    error InvalidSignature();
    error AlreadyRevoked();

    event PolicySet(bytes32 indexed doorId, uint64 version, bytes32 commitment, bool enabled);
    event SessionRevoked(bytes32 indexed doorId, bytes32 indexed sessionRef, address indexed signer);

    function door(bytes32 doorId) external view returns (Door memory) {
        return doors[doorId];
    }

    function authorizationMessage(
        uint8 action,
        address signer,
        bytes32 doorId,
        bytes32 details,
        uint256 nonce,
        uint64 deadline
    ) public view returns (bytes memory) {
        return abi.encode(DOMAIN, block.chainid, address(this), action, signer, doorId, details, nonce, deadline);
    }

    function register(
        bytes32 doorId,
        address owner,
        address account,
        ApprovalPolicy calldata policy,
        uint256 ownerNonce,
        uint256 doorNonce,
        uint64 deadline,
        bytes calldata ownerSignature,
        bytes calldata doorSignature
    ) external {
        if (
            doorId == bytes32(0) || owner == address(0) || account == address(0) || owner == account
                || doors[doorId].version != 0 || doorByAccount[account] != bytes32(0)
        ) revert InvalidDoor();
        validatePolicy(policy);
        bytes32 details = keccak256(abi.encode(owner, account, uint64(1), policy));
        authorize(REGISTER_OWNER, owner, doorId, details, ownerNonce, deadline, ownerSignature);
        authorize(REGISTER_DOOR, account, doorId, details, doorNonce, deadline, doorSignature);
        Door storage record = doors[doorId];
        record.owner = owner;
        record.account = account;
        doorByAccount[account] = doorId;
        setPolicy(record, doorId, 1, policy);
    }

    function updatePolicy(
        bytes32 doorId,
        uint64 version,
        ApprovalPolicy calldata policy,
        uint256 nonce,
        uint64 deadline,
        bytes calldata signature
    ) external {
        Door storage record = doors[doorId];
        if (record.version == 0) revert InvalidDoor();
        if (version != record.version + 1) revert InvalidPolicy();
        validatePolicy(policy);
        bytes32 details = keccak256(abi.encode(version, policy));
        authorize(UPDATE_POLICY, record.owner, doorId, details, nonce, deadline, signature);
        setPolicy(record, doorId, version, policy);
    }

    function revoke(
        bytes32 doorId,
        bytes32 sessionRef,
        uint64 version,
        address signer,
        uint256 nonce,
        uint64 deadline,
        bytes calldata signature
    ) external {
        Door storage record = doors[doorId];
        if (record.version == 0) revert InvalidDoor();
        if (version != record.version || sessionRef == bytes32(0)) revert InvalidPolicy();
        if (signer != record.owner && !canRevoke(record.policy, signer)) revert Unauthorized();
        if (revoked[doorId][sessionRef]) revert AlreadyRevoked();
        bytes32 details = keccak256(abi.encode(version, sessionRef));
        authorize(REVOKE, signer, doorId, details, nonce, deadline, signature);
        revoked[doorId][sessionRef] = true;
        emit SessionRevoked(doorId, sessionRef, signer);
    }

    function canRevoke(ApprovalPolicy storage policy, address signer) private view returns (bool) {
        if (!policy.approversCanRevoke) return false;
        for (uint256 i; i < policy.approvers.length; ++i) {
            if (policy.approvers[i] == signer) return true;
        }
        return false;
    }

    function validatePolicy(ApprovalPolicy calldata policy) private pure {
        if (policy.commitment == bytes32(0) || policy.approvers.length == 0 || policy.approvers.length > 8) {
            revert InvalidPolicy();
        }
        address previous;
        for (uint256 i; i < policy.approvers.length; ++i) {
            address approver = policy.approvers[i];
            if (approver <= previous) revert InvalidPolicy();
            previous = approver;
        }
    }

    function setPolicy(Door storage record, bytes32 doorId, uint64 version, ApprovalPolicy calldata policy) private {
        record.version = version;
        record.policy = policy;
        emit PolicySet(doorId, version, policy.commitment, policy.enabled);
    }

    function authorize(
        uint8 action,
        address signer,
        bytes32 doorId,
        bytes32 details,
        uint256 nonce,
        uint64 deadline,
        bytes calldata signature
    ) private {
        if (block.timestamp >= deadline) revert Expired();
        if (nonce != nonces[signer]) revert InvalidNonce();
        if (signature.length != 4627) revert InvalidSignature();
        (bool registered, uint8 algorithmId, bytes memory key, bool proven) = IPqcKeys(PQC_KEYS).pqcKeyStatus(signer);
        if (!registered || !proven || algorithmId != ML_DSA_87 || key.length != 2592) revert InvalidSignature();
        bytes memory message = authorizationMessage(action, signer, doorId, details, nonce, deadline);
        if (!IPqcVerify(PQC_VERIFY).pqcVerify(key, signature, message)) revert InvalidSignature();
        nonces[signer] = nonce + 1;
    }
}
