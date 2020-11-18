pragma experimental ABIEncoderV2;
import { OVM_BondManager } from "../contracts-v2/contracts/optimistic-ethereum/OVM/verification/OVM_BondManager.sol";

import { OVM_StateTransitioner } from "../contracts-v2/contracts/optimistic-ethereum/OVM/verification/OVM_StateTransitioner.sol";
import { OVM_StateManagerFactory } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_StateManagerFactory.sol";
import { OVM_StateManager } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_StateManager.sol";
import { OVM_ExecutionManager } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_ExecutionManager.sol";
import { iOVM_ExecutionManager } from "../contracts-v2/contracts/optimistic-ethereum/iOVM/execution/iOVM_ExecutionManager.sol";
import { OVM_SafetyChecker } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_SafetyChecker.sol";

import {Lib_AddressResolver} from "../contracts-v2/contracts/optimistic-ethereum/libraries/resolver/Lib_AddressResolver.sol";
import {Lib_AddressManager} from "../contracts-v2/contracts/optimistic-ethereum/libraries/resolver/Lib_AddressManager.sol";
import {Lib_OVMCodec} from "../contracts-v2/contracts/optimistic-ethereum/libraries/codec/Lib_OVMCodec.sol";


import{ERC20} from "../contracts-v2/contracts/optimistic-ethereum/iOVM/verification/iOVM_BondManager.sol";
import {DSTest} from "ds-test/test.sol";

import { OVM_ProxyEOA } from "../contracts-v2/contracts/optimistic-ethereum/OVM/accounts/OVM_ProxyEOA.sol";
import { OVM_ECDSAContractAccount } from "../contracts-v2/contracts/optimistic-ethereum/OVM/accounts/OVM_ECDSAContractAccount.sol";

// Format of tx sent to `executionMgr.run
// struct Transaction {
//     uint256 timestamp;
//     uint256 blockNumber;
//     QueueOrigin l1QueueOrigin;
//     address l1TxOrigin;
//     address entrypoint;
//     uint256 gasLimit;
//     bytes data;
// } where
//  enum QueueOrigin {
//      SEQUENCER_QUEUE,
//      L1TOL2_QUEUE
//  }


contract StateTransiti1onerTest is DSTest {

    bytes constant internal RLP_NULL_BYTES = hex'80';
    bytes constant internal NULL_BYTES = bytes('');
    bytes32 constant internal NULL_BYTES32 = bytes32('');
    bytes32 constant internal KECCAK256_RLP_NULL_BYTES = keccak256(RLP_NULL_BYTES);
    bytes32 constant internal KECCAK256_NULL_BYTES = keccak256(NULL_BYTES);



    
    Lib_AddressManager addressManager;
    
    Lib_AddressResolver resolver;
    OVM_StateManagerFactory stateMgrFactory;
    OVM_StateTransitioner trans;
    OVM_ExecutionManager executionMgr;
    OVM_StateManager stateMgr;
    OVM_SafetyChecker safetyChecker;
    
    function setUp() public {
        addressManager = new Lib_AddressManager();
        stateMgrFactory = new OVM_StateManagerFactory();
        safetyChecker = new OVM_SafetyChecker();
        
        addressManager.setAddress("OVM_StateManagerFactory", address(stateMgrFactory));
        addressManager.setAddress("OVM_SafetyChecker", address(safetyChecker));
        executionMgr = new OVM_ExecutionManager(
                             address(addressManager),
                             iOVM_ExecutionManager.GasMeterConfig(0,0,0,0),
                             iOVM_ExecutionManager.GlobalContext(420) /* blaze it */
                             );
        stateMgr = OVM_StateManager(address(stateMgrFactory.create(address(this))));
        stateMgr.setExecutionManager(address(executionMgr));
        trans = new OVM_StateTransitioner(address(addressManager), 0, 0x0, 0x0);
    }

    function test_sanity() public {
        assertEq(trans.getPreStateRoot(), 0x0);
    }

    function test_run_exe() public {
        // put gas metadata address into state
        stateMgr.putAccount(0x06a506A506a506A506a506a506A506A506A506A5,
                            Lib_OVMCodec.Account(
                                                 0,
                                                 0,
                                                 KECCAK256_RLP_NULL_BYTES,
                                                 KECCAK256_NULL_BYTES,
                                                 address(0),
                                                 false)
                            );
        stateMgr.putContractStorage(0x06a506A506a506A506a506a506A506A506A506A5,
                                    bytes32(0), //bytes32(iOVM_ExecutionManager.GasMetadataKey.CURRENT_EPOCH_START_TIMESTAMP),
                                    bytes32(uint(1))
                            );
        stateMgr.commitContractStorage(0x06a506A506a506A506a506a506A506A506A506A5,
                                       bytes32(0));
        stateMgr.commitAccount(0x06a506A506a506A506a506a506A506A506A506A5);
        executionMgr.run(
          Lib_OVMCodec.Transaction(
            block.timestamp
            ,block.number
            ,Lib_OVMCodec.QueueOrigin.L1TOL2_QUEUE
            ,address(this)
            ,address(0x0) // target
            ,21000 // gaslimit
            ,bytes("") // empty data
          ),
          address(stateMgr)
        );
            
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


