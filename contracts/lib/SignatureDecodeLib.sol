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

    function decodeUse(bytes calldata packedSig) internal pure returns (SignerId signerId, bytes calldata signature) {
        signerId = SignerId.wrap(bytes32(packedSig[1:33]));
        signature = packedSig[33:];
    }

    function decodePackedSigEnable(bytes calldata packedSig)
        internal
        pure
        returns (
            // uint8 permissionIndex,
            bytes calldata permissionEnableData,
            bytes calldata permissionEnableDataSignature,
            bytes calldata permissionData,
            bytes calldata signature
        )
    {
        // TODO: these are just placeholders

        // permissionIndex = uint8(packedSig[1]);
        permissionEnableData = packedSig[2:34];
        permissionEnableDataSignature = packedSig[34:66];
        permissionData = packedSig[66:98];
        signature = packedSig[98:];
    }

    function digest(bytes calldata data) internal pure returns (bytes32) {
        return keccak256(data);
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
}
