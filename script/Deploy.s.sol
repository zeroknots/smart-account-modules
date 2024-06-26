// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Script, console2 } from "forge-std/Script.sol";
import { PermissionManager } from "contracts/validators/PermissionManager.sol";

contract DeployScript is Script {
    function setUp() public { }

    function run() public {
        uint256 privKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privKey);
        bytes memory wcsigner = abi.encodePacked(vm.getCode("./out/WCSigner.sol/WCSigner.json"));

        address cosigner;
        assembly {
            cosigner := create(0, add(wcsigner, 0x20), mload(wcsigner))
        }

        PermissionManager permissionManager = new PermissionManager();

        console2.log("Deployed WCSigner at address: ", cosigner);
        console2.log("Deployed PermissionManager at address: ", address(permissionManager));
    }
}
