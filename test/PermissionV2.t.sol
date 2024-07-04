// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";
import { Solarray } from "solarray/Solarray.sol";
import {
    RhinestoneModuleKit,
    ModuleKitHelpers,
    ModuleKitUserOp,
    AccountInstance,
    UserOpData
} from "modulekit/ModuleKit.sol";
import { MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR, Execution } from "modulekit/external/ERC7579.sol";
import { PermissionManager } from "contracts/PermissionManagerV2.sol";
import { SignatureDecodeLib } from "contracts/lib/SignatureDecodeLib.sol";
import { ISigner } from "contracts/interfaces/ISigner.sol";
import "contracts/DataTypes.sol";
import { YesSigner } from "./mock/YesSigner.sol";
import { MockTarget } from "./mock/MockTarget.sol";
import { YesPolicy } from "./mock/YesPolicy.sol";
import { EIP1271_MAGIC_VALUE, IERC1271 } from "module-bases/interfaces/IERC1271.sol";

import "forge-std/console2.sol";

contract PermissionManagerBaseTest is RhinestoneModuleKit, Test {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;

    // account and modules
    AccountInstance internal instance;
    PermissionManager internal permissionManager;
    YesPolicy internal yesPolicy;
    YesSigner internal yesSigner;

    MockTarget target;
    Account sessionSigner1;
    Account sessionSigner2;

    SignerId defaultSigner1;
    SignerId defaultSigner2;

    function setUp() public {
        instance = makeAccountInstance("smartaccount");

        sessionSigner1 = makeAccount("sessionSigner1");
        sessionSigner2 = makeAccount("sessionSigner2");

        defaultSigner1 = SignerId.wrap(bytes32(hex"01"));
        defaultSigner2 = SignerId.wrap(bytes32(hex"02"));

        permissionManager = new PermissionManager();
        target = new MockTarget();
        yesSigner = new YesSigner();
        yesPolicy = new YesPolicy();

        instance.installModule({ moduleTypeId: MODULE_TYPE_EXECUTOR, module: address(permissionManager), data: "" });

        PolicyConfig[] memory userOpPolicies;
        PolicyConfig[] memory erc1271Policy;
        ActionPolicyConfig[] memory actionPolicies;

        bytes memory initData = abi.encode(userOpPolicies, erc1271Policy, actionPolicies);
        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(permissionManager),
            data: initData
        });

        vm.startPrank(instance.account);
        permissionManager.setSigner(defaultSigner1, ISigner(address(yesSigner)));

        PolicyConfig[] memory policyConfig = new PolicyConfig[](1);
        policyConfig[0] = PolicyConfig({ signerId: defaultSigner1, policies: Solarray.addresses(address(yesPolicy)) });
        permissionManager.setUserOpPolicy(policyConfig);

        vm.stopPrank();
    }

    function test_exec() public {
        UserOpData memory userOpData = instance.getExecOps({
            target: address(target),
            value: 0,
            callData: abi.encodeCall(MockTarget.setValue, (1337)),
            txValidator: address(permissionManager)
        });

        userOpData.userOp.signature =
            SignatureDecodeLib.encodeUse({ signerId: defaultSigner1, packedSig: hex"4141414141" });
        userOpData.execUserOps();
    }

    function test_enable_exec() public {
        UserOpData memory userOpData = instance.getExecOps({
            target: address(target),
            value: 0,
            callData: abi.encodeCall(MockTarget.setValue, (1337)),
            txValidator: address(permissionManager)
        });

        EnableData memory enableData = EnableData({
            actionId: ActionId.wrap(bytes32(hex"01")),
            permissionEnableSig: hex"424242424242",
            userOpPolicies: Solarray.addresses(address(yesPolicy)),
            erc1271Policies: new address[](0),
            actionPolicies: new address[](0)
        });

        userOpData.userOp.signature =
            SignatureDecodeLib.encodePackedSigEnable(defaultSigner1, hex"41414141", enableData);
        userOpData.execUserOps();
    }
}
