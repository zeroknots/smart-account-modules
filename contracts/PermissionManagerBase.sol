import "./DataTypes.sol";
import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as Bytes32Vec,
    ArrayMap4337Lib as AddressVecLib
} from "contracts/lib/ArrayMap4337Lib.sol";

import "./interfaces/ISigner.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
import { Bytes32ArrayMap4337, ArrayMap4337Lib } from "./lib/ArrayMap4337Lib.sol";
import { ConfigLib } from "./lib/ConfigLib.sol";

abstract contract PermissionManagerBase {
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using ArrayMap4337Lib for *;
    using ConfigLib for Policy;
    using ConfigLib for EnumerableActionPolicy;

    Policy internal $userOpPolicies;
    Policy internal $erc1271Policies;
    EnumerableActionPolicy internal $actionPolicies;
    mapping(SignerId => mapping(address smartAccount => ISigner)) internal $isigners;

    function setUserOpPolicy(PolicyConfig[] memory policyConfig) public {
        $userOpPolicies.enable({ policyConfig: policyConfig, smartAccount: msg.sender });
    }

    function setERC1271Policy(PolicyConfig[] memory policyConfig) public {
        $erc1271Policies.enable({ policyConfig: policyConfig, smartAccount: msg.sender });
    }

    function setActionPolicy(ActionPolicyConfig[] memory policyConfig) public {
        $actionPolicies.enable({ actionPolicyConfig: policyConfig, smartAccount: msg.sender });
    }
}
