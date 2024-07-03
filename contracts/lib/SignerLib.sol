import "../DataTypes.sol";
import "../interfaces/ISigner.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import "forge-std/console2.sol";

library SignerLib {
    bytes4 internal constant EIP1271_SUCCESS = 0x1626ba7e;

    error SignerNotFound(SignerId signerId, address account);

    function requireValidISigner(
        mapping(SignerId => mapping(address => ISigner)) storage $isigners,
        bytes32 userOpHash,
        address account,
        SignerId signerId,
        bytes calldata signature
    )
        internal
        view
    {
        console2.logBytes32(SignerId.unwrap(signerId));
        ISigner isigner = $isigners[signerId][account];
        console2.log("checking signature", address(isigner), account);
        if (address(isigner) == address(0)) revert SignerNotFound(signerId, account);

        // check signature of ISigner first.
        // policies only need to be processed if the signature is correct
        if (
            isigner.checkSignature({ signerId: signerId, sender: account, hash: userOpHash, sig: signature })
                != EIP1271_SUCCESS
        ) revert();
    }
}
