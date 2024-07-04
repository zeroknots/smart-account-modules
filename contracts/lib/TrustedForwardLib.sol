import { IModule as IERC7579Module } from "erc7579/interfaces/IERC7579Module.sol";

import "../interfaces/ITrustedForwarder.sol";
import "forge-std/interfaces/IERC165.sol";
import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { ModeCode } from "erc7579/lib/ModeLib.sol";

library TrustedForwardLib {
    using TrustedForwardLib for address;

    error TrustedForwarderCallFailed();

    function fwdCall(
        address target,
        bytes memory callData,
        address forAccount
    )
        internal
        returns (bytes memory returnData)
    {
        bool success;
        (success, returnData) = target.call(abi.encodePacked(callData, address(this), forAccount));
        if (!success) revert();
    }

    function initFwd(address subModule, bytes32 id, address smartAccount, bytes memory subModuleInitData) internal {
        try IERC165(subModule).supportsInterface(type(ITrustedForwarder).interfaceId) returns (bool supported) {
            if (supported) {
                if (!ITrustedForwarder(subModule).isTrustedForwarder(address(this), smartAccount, id)) {
                    IERC7579Account(smartAccount).executeFromExecutor(
                        ModeCode.wrap(0),
                        ExecutionLib.encodeSingle(
                            subModule, 0, abi.encodeCall(ITrustedForwarder.setTrustedForwarder, (address(this), id))
                        )
                    );
                }
                subModule.fwdCall({
                    callData: abi.encodeCall(IERC7579Module.onInstall, (subModuleInitData)),
                    forAccount: smartAccount
                });
            } else {
                revert TrustedForwarderCallFailed();
            }
        } catch (bytes memory) /*error*/ {
            revert TrustedForwarderCallFailed();
        }
    }
}
