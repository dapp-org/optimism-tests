pragma experimental ABIEncoderV2;

import { iOVM_ExecutionManager } from "../contracts-v2/contracts/optimistic-ethereum/iOVM/execution/iOVM_ExecutionManager.sol";
import{ ERC20 } from "../contracts-v2/contracts/optimistic-ethereum/iOVM/verification/iOVM_BondManager.sol";

import { Lib_AddressResolver } from "../contracts-v2/contracts/optimistic-ethereum/libraries/resolver/Lib_AddressResolver.sol";
import { Lib_AddressManager } from "../contracts-v2/contracts/optimistic-ethereum/libraries/resolver/Lib_AddressManager.sol";
import { Lib_OVMCodec } from "../contracts-v2/contracts/optimistic-ethereum/libraries/codec/Lib_OVMCodec.sol";
import { Lib_SafeExecutionManagerWrapper } from "../contracts-v2/contracts/optimistic-ethereum/libraries/wrappers/Lib_SafeExecutionManagerWrapper.sol";

import { OVM_StateTransitioner } from "../contracts-v2/contracts/optimistic-ethereum/OVM/verification/OVM_StateTransitioner.sol";
import { OVM_StateManagerFactory } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_StateManagerFactory.sol";
import { OVM_StateManager } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_StateManager.sol";
import { OVM_ExecutionManager } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_ExecutionManager.sol";
import { OVM_SafetyChecker } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_SafetyChecker.sol";

import { OVM_ProxyEOA } from "../contracts-v2/contracts/optimistic-ethereum/OVM/accounts/OVM_ProxyEOA.sol";
import { OVM_ECDSAContractAccount } from "../contracts-v2/contracts/optimistic-ethereum/OVM/accounts/OVM_ECDSAContractAccount.sol";

import { DSTest } from "ds-test/test.sol";

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
            iOVM_ExecutionManager.GasMeterConfig({
                minTransactionGasLimit: 0,
                maxTransactionGasLimit: 1000000000,
                maxGasPerQueuePerEpoch: 250000000,
                secondsPerEpoch:        60
            }),
            iOVM_ExecutionManager.GlobalContext(420) /* blaze it */
        );

        stateMgr = OVM_StateManager(address(stateMgrFactory.create(address(this))));
        writeGasMetaData();

        stateMgr.setExecutionManager(address(executionMgr));
        trans = new OVM_StateTransitioner(address(addressManager), 0, 0x0, 0x0);
    }

    function test_trivial_run_exe() public {
        executionMgr.run(
            Lib_OVMCodec.Transaction({
                timestamp:     block.timestamp,
                blockNumber:   block.number,
                l1QueueOrigin: Lib_OVMCodec.QueueOrigin.L1TOL2_QUEUE,
                l1TxOrigin:    address(this),
                entrypoint:    address(0),
                gasLimit:      21000,
                data:          bytes("")
            }),
            address(stateMgr)
        );
    }

    function test_decodeTx() public {
        Lib_OVMCodec.decodeEIP155Transaction(
            hex"f85f800180946888c043d3c793764a012b209e51ba766877f553808082036ca02a1f1c8ce0ccce461a8177117ff655ffd3e948dfecf4a27005ba0a74deab462da0347a6b843050f04ead7f8e7e46aaf29a1dde97dad0a3f42496df69b326f7e309",
            false
        );
    }

    function testEOA(bytes memory a) public {
        spinupEOA();
        executionMgr.ovmCALL(gasleft(), 0x3E17BDA2f18fB29756a6B82A48ec75Fe291C1374, a);
    }


    function test_create_contract() public {
        address target = address(new MakeEmpty());
        liftToL2(address(target));
        stateMgr.putEmptyAccount(0x42d454D12b11EdfB2e5cb8c90e6809a4E4925Ee5);

        executionMgr.run(
            Lib_OVMCodec.Transaction({
                timestamp:     block.timestamp,
                blockNumber:   block.number,
                l1QueueOrigin: Lib_OVMCodec.QueueOrigin.L1TOL2_QUEUE,
                l1TxOrigin:    address(this),
                entrypoint:    target,
                gasLimit:      uint64(-1),
                data:          abi.encodeWithSignature("build()")
            }),
            address(stateMgr)
        );
    }

    // --- Utils ---

    function writeGasMetaData() public {
        address gas_metadata_address = 0x06a506A506a506A506a506a506A506A506A506A5;
        stateMgr.putAccount(
            gas_metadata_address,
            Lib_OVMCodec.Account({
                nonce:       0,
                balance:     0,
                storageRoot: KECCAK256_RLP_NULL_BYTES,
                codeHash:    KECCAK256_NULL_BYTES,
                ethAddress:  address(0),
                isFresh:     false
            })
        );

        // write every GasMetadataKey
        for (uint i = 0; i <= 4; i++) {
            writeStorage(gas_metadata_address, bytes32(i), bytes32(uint(1)));
        }

        stateMgr.commitAccount(gas_metadata_address);

        // test and set all metadata keys
        for (uint i = 0; i <= 4; i++) {
            stateMgr.testAndSetContractStorageLoaded(gas_metadata_address, bytes32(i));
        }
    }

    function writeStorage(address target, bytes32 key, bytes32 val) public {
        stateMgr.putContractStorage(target, key, val);
        stateMgr.commitContractStorage(target, key);
    }

    function spinupEOA() public {
        hevm.store(address(executionMgr), bytes32(uint(2)), bytes32(uint(address(stateMgr))));
        stateMgr.putEmptyAccount(0x3E17BDA2f18fB29756a6B82A48ec75Fe291C1374);
        stateMgr.testAndSetAccountChanged(0x3E17BDA2f18fB29756a6B82A48ec75Fe291C1374);
        executionMgr.ovmCREATEEOA(
            0x03ab237a027f9be39cae8f0b7ba5c0c5fb9ddaac373371c1283eb972cfbb5db1,
            0,
            0x581f1fa4a220851d3821909b68a38c9fed9094bb2830094d847ed4c8fb30b34d,
            0x657f781894e53e78fb97f1edd6376c99fba7f86c7a674e48b7edc18222c1c3ea
        );
    }

    function liftToL2(address acc) public {
        putAccountAt(acc, acc);
    }

    function putAccountAt(address from, address to) public {
        bytes32 codeHash; assembly { codeHash := extcodehash(to) }
        stateMgr.putAccount(
            from,
            Lib_OVMCodec.Account({
                nonce:       0,
                balance:     0,
                storageRoot: KECCAK256_RLP_NULL_BYTES,
                codeHash:    codeHash,
                ethAddress:  to,
                isFresh:     false
            })
        );
        stateMgr.commitAccount(to);
        stateMgr.testAndSetAccountLoaded(to);
    }
}

contract MakeEmpty {
    constructor() {}

    function build() public {
        Lib_SafeExecutionManagerWrapper.safeCREATE(
            gasleft(), type(Empty).creationCode
        );
    }
}

contract Empty {
    constructor() payable {}
    fallback() external payable {}
}

library Utils {
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
