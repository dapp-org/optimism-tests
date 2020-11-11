import { OVM_BondManager } from "../contracts-v2/contracts/optimistic-ethereum/OVM/verification/OVM_BondManager.sol";

import { OVM_StateTransitioner } from "../contracts-v2/contracts/optimistic-ethereum/OVM/verification/OVM_StateTransitioner.sol";
import { OVM_StateManagerFactory } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_StateManagerFactory.sol";

import {Lib_AddressResolver} from "../contracts-v2/contracts/optimistic-ethereum/libraries/resolver/Lib_AddressResolver.sol";
import {Lib_AddressManager} from "../contracts-v2/contracts/optimistic-ethereum/libraries/resolver/Lib_AddressManager.sol";


import{ERC20} from "../contracts-v2/contracts/optimistic-ethereum/iOVM/verification/iOVM_BondManager.sol";
import {DSTest} from "ds-test/test.sol";

import { OVM_ProxyEOA } from "../contracts-v2/contracts/optimistic-ethereum/OVM/accounts/OVM_ProxyEOA.sol";


contract StateTransiti1onerTest is DSTest {
    Lib_AddressManager addressManager;
    
    Lib_AddressResolver resolver;
    OVM_StateManagerFactory stateMgrFactory;
    OVM_StateTransitioner trans;
    
    function setUp() public {
        addressManager = new Lib_AddressManager();
        stateMgrFactory = new OVM_StateManagerFactory();
        addressManager.setAddress("OVM_StateManagerFactory", address(stateMgrFactory));
        trans = new OVM_StateTransitioner(address(addressManager), 0, 0x0, 0x0);
    }

    function test_sanity() public {
        assertEq(trans.getPreStateRoot(), 0x0);
    }
}


contract BondManagerTest is DSTest {
    Lib_AddressManager manager;
    Lib_AddressResolver resolver;
    OVM_BondManager mgr;

    function setUp() public {
        manager = new Lib_AddressManager();
        mgr = new OVM_BondManager(ERC20(address(0x00)), address(manager));
    }
    function test_a() public {
        assertEq(address(mgr.token()), address(0x00));
    }
    function prove_a() public {
        assertEq(address(mgr.token()), address(0x00));
    }
}


// some loose ideas here... this might be junk.
/* contract MerkleTreeTest is DSTest, Lib_MerkleTree { */

/*     // the witness format of the Merkle Tree is from */
/*     // https://github.com/ethereumjs/merkle-patricia-tree/ */
/*     function getRoot(bytes32[] keys, bytes32 vals) public returns (bytes32) { */
/*         require(keys.length == vals.length, "wrong"); */
/*         bytes32 root = KECCAK256_RLP_NULL_BYTES; */
/*         for (uint i; i < keys.length; i++) { */
/*             root = update(abi.encodePacked(keys[i]), abi.encodePacked(values[i]), root); */
/*         } */
/*     } */
/* } */


