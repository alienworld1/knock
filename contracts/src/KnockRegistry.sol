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
    uint8 public constant SET_OFFER = 5;
    uint8 public constant PURCHASE = 6;
    uint8 public constant CONSUME = 7;

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

    struct Offer {
        bytes32 id;
        uint64 version;
        uint64 duration;
        uint256 amount;
        address beneficiary;
    }

    struct Purchase {
        bytes32 doorId;
        address buyer;
        Offer offer;
        uint64 redeemBy;
        bytes32 sessionRef;
    }

    mapping(address => uint256) public nonces;
    mapping(address => bytes32) public doorByAccount;
    mapping(bytes32 => Door) private doors;
    mapping(bytes32 => mapping(bytes32 => bool)) public revoked;
    mapping(bytes32 => Offer) public offers;
    mapping(bytes32 => Purchase) private purchases;

    error InvalidDoor();
    error InvalidPolicy();
    error Unauthorized();
    error InvalidNonce();
    error Expired();
    error InvalidSignature();
    error AlreadyRevoked();
    error InvalidOffer();
    error InvalidPurchase();
    error SettlementFailed();

    event PolicySet(bytes32 indexed doorId, uint64 version, bytes32 commitment, bool enabled);
    event SessionRevoked(bytes32 indexed doorId, bytes32 indexed sessionRef, address indexed signer);
    event OfferSet(bytes32 indexed doorId, bytes32 indexed offerId, uint64 version);
    event PassPurchased(bytes32 indexed commitment, bytes32 indexed doorId, address indexed buyer, bytes32 offerId);
    event PassConsumed(bytes32 indexed commitment, bytes32 indexed doorId, bytes32 indexed sessionRef);

    function door(bytes32 doorId) external view returns (Door memory) {
        return doors[doorId];
    }

    function purchase(bytes32 commitment) external view returns (Purchase memory) {
        return purchases[commitment];
    }

    function setOffer(bytes32 doorId, Offer calldata offer, uint256 nonce, uint64 deadline, bytes calldata signature)
        external
    {
        Door storage record = doors[doorId];
        if (
            !metered(record, offer.version) || offer.id == bytes32(0) || offer.duration == 0 || offer.duration > 3600
                || offer.amount == 0 || offer.amount % 1e12 != 0 || offer.beneficiary == address(0)
                || offer.beneficiary == address(this) || offers[doorId].version == offer.version
        ) revert InvalidOffer();
        authorize(SET_OFFER, record.owner, doorId, keccak256(abi.encode(offer)), nonce, deadline, signature);
        offers[doorId] = offer;
        emit OfferSet(doorId, offer.id, offer.version);
    }

    function purchasePass(
        bytes32 doorId,
        Offer calldata offer,
        bytes32 commitment,
        uint256 nonce,
        uint64 redeemBy,
        bytes calldata signature
    ) external payable {
        bytes32 terms = keccak256(abi.encode(offer));
        if (
            !metered(doors[doorId], offer.version) || offer.id == bytes32(0)
                || terms != keccak256(abi.encode(offers[doorId])) || msg.value != offer.amount
        ) revert InvalidOffer();
        if (commitment == bytes32(0) || purchases[commitment].buyer != address(0)) revert InvalidPurchase();
        authorize(PURCHASE, msg.sender, doorId, keccak256(abi.encode(terms, commitment)), nonce, redeemBy, signature);
        purchases[commitment] = Purchase(doorId, msg.sender, offer, redeemBy, bytes32(0));
        (bool paid,) = offer.beneficiary.call{value: msg.value}("");
        if (!paid) revert SettlementFailed();
        emit PassPurchased(commitment, doorId, msg.sender, offer.id);
    }

    function consumePass(
        bytes32 doorId,
        uint64 version,
        bytes32 commitment,
        bytes32 sessionRef,
        uint256 nonce,
        uint64 deadline,
        bytes calldata signature
    ) external {
        Door storage record = doors[doorId];
        Purchase storage pass = purchases[commitment];
        if (msg.sender != record.account) revert Unauthorized();
        if (
            !metered(record, version) || pass.doorId != doorId || pass.offer.version != version
                || pass.sessionRef != bytes32(0) || sessionRef == bytes32(0) || revoked[doorId][sessionRef]
                || deadline > pass.redeemBy
        ) revert InvalidPurchase();
        bytes32 details = keccak256(abi.encode(version, commitment, sessionRef));
        authorize(CONSUME, record.account, doorId, details, nonce, deadline, signature);
        pass.sessionRef = sessionRef;
        emit PassConsumed(commitment, doorId, sessionRef);
    }

    function metered(Door storage record, uint64 version) private view returns (bool) {
        return version != 0 && record.version == version && record.policy.enabled && record.policy.approvers.length == 0;
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
        if (
            policy.commitment == bytes32(0) || policy.approvers.length > 8
                || (policy.approvers.length == 0 && policy.approversCanRevoke)
        ) {
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
