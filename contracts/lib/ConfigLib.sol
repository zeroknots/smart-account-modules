import "../DataTypes.sol";
import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as BytesVec,
    ArrayMap4337Lib as AddressVecLib
} from "./ArrayMap4337Lib.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
import { Bytes32ArrayMap4337, ArrayMap4337Lib } from "./ArrayMap4337Lib.sol";

library ConfigLib {
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using ConfigLib for Policy;
    using ArrayMap4337Lib for *;

    function enable(Policy storage $policy, PolicyConfig[] memory policyConfig, address smartAccount) internal {
        uint256 lengthConfigs = policyConfig.length;

        // TODO: trusted forward check

        for (uint256 i; i < lengthConfigs; i++) {
            PolicyConfig memory config = policyConfig[i];

            uint256 lengthPolicies = config.policies.length;

            for (uint256 y; y < lengthPolicies; y++) {
                $policy.policyList[config.signerId].push(smartAccount, config.policies[i]);
            }
        }
    }

    function enable(
        EnumerableActionPolicy storage $self,
        ActionPolicyConfig[] memory actionPolicyConfig,
        address smartAccount
    )
        internal
    {
        uint256 length = actionPolicyConfig.length;

        for (uint256 i; i < length; i++) {
            // record every enabled actionId
            ActionPolicyConfig memory config = actionPolicyConfig[i];
            $self.enabledActionIds.push(smartAccount, ActionId.unwrap(config.actionId));
            $self.actionPolicies[config.actionId].enable(config.policyConfig, smartAccount);
        }
    }

    function enable(
        EnumerableActionPolicy storage $self,
        address[] memory policies,
        ActionId actionId,
        SignerId signerId,
        address smartAccount
    )
        internal
    {
        $self.enabledActionIds.push(smartAccount, ActionId.unwrap(actionId));
        $self.actionPolicies[actionId].enable(policies, signerId, smartAccount);
    }

    function enable(
        Policy storage $policy,
        address[] memory policies,
        SignerId signerId,
        address smartAccount
    )
        internal
    {
        uint256 lengthPolicies = policies.length;

        for (uint256 i; i < lengthPolicies; i++) {
            $policy.policyList[signerId].push(smartAccount, policies[i]);
        }
    }
}
