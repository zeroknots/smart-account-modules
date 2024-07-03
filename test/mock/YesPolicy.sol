// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import { _packValidationData } from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";

import "forge-std/console2.sol";

// This submodule doesn't need to be TrustedForwarder as both checks are view

contract YesPolicy is IUserOpPolicy, IActionPolicy {
    function isInitialized(address smartAccount) external view returns (bool) { }

    function onInstall(bytes calldata data) external { }

    function onUninstall(bytes calldata data) external { }

    function isModuleType(uint256 id) external pure returns (bool) { }

    function checkUserOp(SignerId id, PackedUserOperation calldata userOp) external override returns (uint256) {
        return 0;
    }

    function checkAction(
        ActionPolicyId id,
        address target,
        uint256 value,
        bytes calldata data,
        PackedUserOperation calldata userOp
    )
        external
        override
        returns (uint256)
    {
        return 0;
    }
}
