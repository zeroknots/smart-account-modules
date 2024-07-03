import "../DataTypes.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";

library SignatureDecodeLib {
    function decodeMode(PackedUserOperation calldata userOp)
        internal
        pure
        returns (PermissionManagerMode mode, bytes calldata packedSig)
    {
        mode = PermissionManagerMode(uint8(bytes1(userOp.signature[:1])));
        packedSig = userOp.signature[1:];
    }

    function encodeUse(SignerId signerId, bytes memory packedSig) internal pure returns (bytes memory userOpSig) {
        userOpSig = abi.encodePacked(PermissionManagerMode.USE, signerId, packedSig);
    }

    function decodeUse(bytes calldata packedSig) internal pure returns (SignerId signerId, bytes calldata signature) {
        signerId = SignerId.wrap(bytes32(packedSig[0:32]));
        signature = packedSig[32:];
    }

    function decodePackedSigEnable(bytes calldata packedSig) internal pure returns (EnableData memory enableData) {
        enableData = abi.decode(packedSig, (EnableData));
    }

    function digest(EnableData memory data) internal pure returns (bytes32) {
        // TODO add chainId
        return keccak256(abi.encode(data.userOpPolicies, data.erc1271Policies, data.actionPolicies));
    }

    function decodeEnable(bytes calldata enableData)
        internal
        pure
        returns (
            address[] memory userOpPolicies,
            address[] memory erc1271Policy,
            ActionId actionId,
            address[] memory actionPolicies
        )
    {
        (userOpPolicies, erc1271Policy, actionId, actionPolicies) =
            abi.decode(enableData, (address[], address[], ActionId, address[]));
    }

    function encodeEnable(
        address[] memory userOpPolicies,
        address[] memory erc1271Policy,
        ActionId actionId,
        address[] memory actionPolicies
    )
        internal
        pure
        returns (bytes memory enableData)
    {
        enableData = abi.encode(userOpPolicies, erc1271Policy, actionId, actionPolicies);
        enableData = abi.encodePacked(PermissionManagerMode.UNSAFE_ENABLE, enableData);
    }

    function decodeInstall(bytes calldata enableData)
        internal
        pure
        returns (
            PolicyConfig[] memory userOpPolicies,
            PolicyConfig[] memory erc1271Policy,
            ActionPolicyConfig[] memory actionPolicies
        )
    {
        (userOpPolicies, erc1271Policy, actionPolicies) =
            abi.decode(enableData, (PolicyConfig[], PolicyConfig[], ActionPolicyConfig[]));
    }
}
