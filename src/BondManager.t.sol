import { OVM_BondManager } from "../contracts-v2/contracts/optimistic-ethereum/OVM/verification/OVM_BondManager.sol";
import {Lib_AddressResolver} from "../contracts-v2/contracts/optimistic-ethereum/libraries/resolver/Lib_AddressResolver.sol";
import {Lib_AddressManager} from "../contracts-v2/contracts/optimistic-ethereum/libraries/resolver/Lib_AddressManager.sol";
import{ERC20} from "../contracts-v2/contracts/optimistic-ethereum/iOVM/verification/iOVM_BondManager.sol";
import {DSTest} from "ds-test/test.sol";

contract BondManagerTest is DSTest {
    Lib_AddressManager manager;
    Lib_AddressResolver resolver;
    OVM_BondManager mgr;

    function setUp() public {
        manager = new Lib_AddressManager();
        // resolver = new Lib_AddressResolver(address(manager));
        mgr = new OVM_BondManager(ERC20(address(0x00)),address(manager));
    }
    function test_a() public {
        assertEq(address(mgr.token()), address(0x00));
    }
    function prove_a() public {
        assertEq(address(mgr.token()), address(0x00));
    }
}
