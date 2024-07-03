import "./lib/ArrayMap4337Lib.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";

type SignerId is bytes32;

type ActionId is bytes32;

type ActionPolicyId is bytes32;

type SignedActionId is bytes32;

function toActionPolicyId(SignerId signerId, ActionId actionId) pure returns (ActionPolicyId policyId) {
    policyId = ActionPolicyId.wrap(keccak256(abi.encodePacked(SignerId.unwrap(signerId), ActionId.unwrap(actionId))));
}

function toSignedActionId(SignerId signerId, ActionId actionId) pure returns (SignedActionId policyId) {
    policyId = SignedActionId.wrap(
        keccak256(abi.encodePacked("ERC1271: ", SignerId.unwrap(signerId), ActionId.unwrap(actionId)))
    );
}

struct PolicyConfig {
    SignerId signerId;
    address[] policies;
}

struct ActionPolicyConfig {
    ActionId actionId;
    PolicyConfig[] policyConfig;
}

type PermissionDescriptor is bytes4;

enum PermissionManagerMode {
    USE,
    ENABLE,
    UNSAFE_ENABLE
}

struct Policy {
    mapping(SignerId => SentinelList4337Lib.SentinelList) policyList;
}

struct EnumerableActionPolicy {
    mapping(ActionId => Policy) actionPolicies;
    Bytes32ArrayMap4337 enabledActionIds;
}
