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

interface Hevm {
    function warp(uint256) external;
    function store(address,bytes32,bytes32) external;
}

contract StateTransiti1onerTest is DSTest {
    bytes constant internal RLP_NULL_BYTES = hex'80';
    bytes constant internal NULL_BYTES = bytes('');
    bytes32 constant internal NULL_BYTES32 = bytes32('');
    bytes32 constant internal KECCAK256_RLP_NULL_BYTES = keccak256(RLP_NULL_BYTES);
    bytes32 constant internal KECCAK256_NULL_BYTES = keccak256(NULL_BYTES);



    Hevm hevm;
    Lib_AddressManager addressManager;

    Lib_AddressResolver resolver;
    OVM_StateManagerFactory stateMgrFactory;
    OVM_StateTransitioner trans;
    OVM_ExecutionManager executionMgr;
    OVM_StateManager stateMgr;
    OVM_SafetyChecker safetyChecker;

    function setUp() public {
        hevm = Hevm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
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

    function test_trivial_run_exe() public {
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
        stateMgr.testAndSetContractStorageLoaded(0x06a506A506a506A506a506a506A506A506A506A5,
                                                 bytes32(0));
        executionMgr.run(
          Lib_OVMCodec.Transaction(
            block.timestamp
            ,block.number
            ,Lib_OVMCodec.QueueOrigin.L1TOL2_QUEUE
            ,address(this)
            ,address(0) // target
            ,21000       // gaslimit
            ,bytes("")  // empty data
          ),
          address(stateMgr)
        );
    }

    function liftToL2(address acc) public {
        putAccountAt(acc, acc);
    }

    function putAccountAt(address from, address to) public {
        stateMgr.putAccount(from,
                            Lib_OVMCodec.Account(
                                                 0,
                                                 0,
                                                 KECCAK256_RLP_NULL_BYTES,
                                                 KECCAK256_NULL_BYTES,
                                                 to,
                                                 false)
                            );

    }

    function test_decodeTx() public {
        Lib_OVMCodec.decodeEIP155Transaction(
                                             hex"f85f800180946888c043d3c793764a012b209e51ba766877f553808082036ca02a1f1c8ce0ccce461a8177117ff655ffd3e948dfecf4a27005ba0a74deab462da0347a6b843050f04ead7f8e7e46aaf29a1dde97dad0a3f42496df69b326f7e309", false);
    }

    function spinupEOA() public {
        hevm.store(address(executionMgr), bytes32(uint(2)), bytes32(uint(address(stateMgr))));
        stateMgr.putEmptyAccount(0x3E17BDA2f18fB29756a6B82A48ec75Fe291C1374);
        stateMgr.testAndSetAccountChanged(0x3E17BDA2f18fB29756a6B82A48ec75Fe291C1374);
        executionMgr.ovmCREATEEOA(
                                  0x03ab237a027f9be39cae8f0b7ba5c0c5fb9ddaac373371c1283eb972cfbb5db1,
                                  0,
                                  0x581f1fa4a220851d3821909b68a38c9fed9094bb2830094d847ed4c8fb30b34d,
                                  0x657f781894e53e78fb97f1edd6376c99fba7f86c7a674e48b7edc18222c1c3ea);
    }

    function testEOA(bytes memory a) public {
        spinupEOA();
        executionMgr.ovmCALL(gasleft(), 0x3E17BDA2f18fB29756a6B82A48ec75Fe291C1374, a);
    }


    function test_initcode_revert() public {
        executionMgr.run(
            Lib_OVMCodec.Transaction(
                block.timestamp,
                block.number,
                Lib_OVMCodec.QueueOrigin.L1TOL2_QUEUE,
                address(this),
                address(this), // target
                21000,         // gaslimit
                abi.encodeWithSignature("ovmCREATE(bytes)", type(Broken).creationCode)
            ),
            address(stateMgr)
        );
    }
}

contract Broken {
    constructor(address exec) {
        (bool res, bytes memory data) = exec.call(
            abi.encodeWithSignature("ovmSLOAD(bytes32)", 666)
        );

        if (!res) {
            (uint flag,,,) = decodeRevertData(data);
            if (iOVM_ExecutionManager.RevertFlag(flag)
                    == iOVM_ExecutionManager.RevertFlag.INVALID_STATE_ACCESS) {
                while (true) {
                    assembly { pop(0) } // force a revert by underflowing the stack
                }
            }

        }
    }

    function decodeRevertData(
        bytes memory revertdata
    )
        internal pure
        returns (uint256 flag, uint256 nuisanceGasLeft, uint256 ovmGasRefund, bytes memory data)
    {
        if (revertdata.length == 0) {
            return (0, 0, 0, bytes(''));
        }
        return abi.decode(revertdata, (uint256, uint256, uint256, bytes));
    }
}


/* contract BondManagerTest is DSTest { */
/*     Lib_AddressManager manager; */
/*     Lib_AddressResolver resolver; */
/*     OVM_BondManager mgr; */

/*     function setUp() public { */
/*         manager = new Lib_AddressManager(); */
/*         mgr = new OVM_BondManager(ERC20(address(0x00)), address(manager)); */
/*     } */
/*     function test_a() public { */
/*         assertEq(address(mgr.token()), address(0x00)); */
/*     } */
/*     function prove_a() public { */
/*         assertEq(address(mgr.token()), address(0x00)); */
/*     } */
/* } */

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