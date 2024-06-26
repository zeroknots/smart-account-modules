// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

address constant NO_SIGNATURE_VALIDATION_REQUIRED = address(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF);

interface IPermissionManager {
    type SignerId is bytes32;
    type ActionId is bytes32;

    error ExecuteUserOpIsNotSupported();

    error PolicyAlreadyUsed(address userOpPolicy);
}
