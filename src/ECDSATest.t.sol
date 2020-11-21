pragma experimental ABIEncoderV2;

import { iOVM_ExecutionManager } from "../contracts-v2/contracts/optimistic-ethereum/iOVM/execution/iOVM_ExecutionManager.sol";
import { Lib_AddressResolver } from "../contracts-v2/contracts/optimistic-ethereum/libraries/resolver/Lib_AddressResolver.sol";
import { Lib_AddressManager } from "../contracts-v2/contracts/optimistic-ethereum/libraries/resolver/Lib_AddressManager.sol";
import { Lib_OVMCodec } from "../contracts-v2/contracts/optimistic-ethereum/libraries/codec/Lib_OVMCodec.sol";
import { Lib_RLPWriter } from "../contracts-v2/contracts/optimistic-ethereum/libraries/rlp/Lib_RLPWriter.sol";
import { Lib_RLPReader } from "../contracts-v2/contracts/optimistic-ethereum/libraries/rlp/Lib_RLPReader.sol";
import { Lib_ECDSAUtils } from "../contracts-v2/contracts/optimistic-ethereum/libraries/utils/Lib_ECDSAUtils.sol";
import { Lib_SafeExecutionManagerWrapper } from "../contracts-v2/contracts/optimistic-ethereum/libraries/wrappers/Lib_SafeExecutionManagerWrapper.sol";

import { OVM_StateTransitioner } from "../contracts-v2/contracts/optimistic-ethereum/OVM/verification/OVM_StateTransitioner.sol";
import { OVM_StateManagerFactory } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_StateManagerFactory.sol";
import { OVM_StateManager } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_StateManager.sol";
import { OVM_ExecutionManager } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_ExecutionManager.sol";
import { OVM_SafetyChecker } from "../contracts-v2/contracts/optimistic-ethereum/OVM/execution/OVM_SafetyChecker.sol";

import { OVM_ProxyEOA } from "../contracts-v2/contracts/optimistic-ethereum/OVM/accounts/OVM_ProxyEOA.sol";
import { OVM_ECDSAContractAccount } from "../contracts-v2/contracts/optimistic-ethereum/OVM/accounts/OVM_ECDSAContractAccount.sol";

import { DSTest } from "ds-test/test.sol";
import "./ERC20Setup.sol";

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
    address constant RELAYER_TOKEN_ADDRESS = 0x4200000000000000000000000000000000000006;
    address constant TEST_EOA = 0xD521C744831cFa3ffe472d9F5F9398c9Ac806203;

    Hevm hevm;
    Lib_AddressManager addressManager;

    ERC20Setup erc20Setup;
    address ovmERC20Address;

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

        erc20Setup = new ERC20Setup();
        ovmERC20Address = erc20Setup.deployTokenContract();

        addressManager.setAddress("OVM_StateManagerFactory", address(stateMgrFactory));
        addressManager.setAddress("OVM_SafetyChecker", address(safetyChecker));

        executionMgr = new OVM_ExecutionManager(
            address(addressManager),
            iOVM_ExecutionManager.GasMeterConfig({
                minTransactionGasLimit: 0,
                maxTransactionGasLimit: 1000000000,
                maxGasPerQueuePerEpoch: 250000000,
                secondsPerEpoch:        600
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

    function test_upgrade_eoa() public {
        address eoa = TEST_EOA;
        address empty = address(new Empty());
        liftToL2(empty);
        stateMgr.putEmptyAccount(eoa);
        deployEOA();

        executionMgr.run(
            Lib_OVMCodec.Transaction({
                timestamp:     block.timestamp,
                blockNumber:   block.number,
                l1QueueOrigin: Lib_OVMCodec.QueueOrigin.L1TOL2_QUEUE,
                l1TxOrigin:    address(this),
                entrypoint:    eoa,
                gasLimit:      100000000,
                data:          abi.encodeWithSignature("upgrade(address)", empty)
            }),
            address(stateMgr)
        );

        hevm.store(address(executionMgr), bytes32(uint(2)), bytes32(uint(address(stateMgr))));
        (bool res, bytes memory data) = executionMgr.ovmCALL(uint(-1), eoa, abi.encodeWithSignature("getImplementation"));
        require(res, "cannot get impl");
        address impl = abi.decode(data, (address));

        assertEq(impl, empty);
    }

    // demonstrates successful gas overflow in the ECDSAContractAccount
    // generated with ./sign with the following modification:
    // TX=$(ethsign tx --to "$1" --from "$FROM" --chain-id 420 --gas-price 0x346dc5d63886594af4f0d844d013a92a305532617c1bda5119ce075f6fd22  --passphrase-file optimistic --key-store secrets --nonce 1 --value 0 --gas-limit 20000)
    function testGasOverflow() public {
        uint256 nonce = 1;
        uint256 gasPrice = 0x346dc5d63886594af4f0d844d013a92a305532617c1bda5119ce075f6fd22;
        uint256 gasLimit = 20000;
        address to = TEST_EOA;
        uint256 value = 0;
        bytes memory data = "";
        uint256 chainId = 420;
        bytes memory exampleTx = Lib_OVMCodec.encodeEIP155Transaction(
            Lib_OVMCodec.EIP155Transaction(
                nonce,
                gasPrice,
                gasLimit,
                to, // same as signer
                value,
                data,
                chainId
            ),
            false
        );

        bytes32 balanceVal = bytes32(uint(25000));
        writeStorage(RELAYER_TOKEN_ADDRESS, 0xb8382f520cd2a1c79d81a7bbfa002fe9522bb06f3ac162a0294c8c6a4c3e03f3, balanceVal);
        writeStorage(RELAYER_TOKEN_ADDRESS, 0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5, 0);
        // Set messageRecord.nuisanceGasLeft to 50000
        hevm.store(address(executionMgr), bytes32(uint(17)), bytes32(uint(50000)));
        install_ETH_ERC20();
        deployEOA();
        // --- PRE STATE ----
        // ovmCALLER is actually 0 here
        assertEq(balanceOf(address(0)), 0);
        assertEq(balanceOf(TEST_EOA), 25000);

        bytes32 exampleTxHash = keccak256(exampleTx);
        log_bytes32(exampleTxHash);

        executionMgr.ovmCALL(
            gasleft(),
            TEST_EOA,
            abi.encodeWithSignature(
                "execute(bytes,uint8,uint8,bytes32,bytes32)",
                exampleTx,
                0,
                1,
                0x91c5fce61765ba44cbead9c49b353d82ac32c882ea20a42ae0214659a2606c57,
                0x29378557ddf674f2d0520e1fec9ad91a4165170fab29d2c454e46f1d539f6115
            )
        );

        // --- POST STATE ---
        assertEq(balanceOf(TEST_EOA), 25000 - 64);
        assertEq(balanceOf(address(0)), 64);
    }

    // in ./sign
    // gasLimit 200
    // gasPrice 0
    // to TEST_EOA
    // TX=$(ethsign tx --to 0xD521C744831cFa3ffe472d9F5F9398c9Ac806203 --from "$FROM" --chain-id 420 --gas-price 0  --passphrase-file optimistic --key-store secrets --nonce 1 --value 0 --gas-limit 200)
    function test_underflow_gascap() public {
        uint256 nonce = 1;
        uint256 gasPrice = 0;
        uint256 gasLimit = 200;
        address to = TEST_EOA;
        uint256 value = 0;
        bytes memory data = "";
        uint256 chainId = 420;
        bytes memory exampleTx = Lib_OVMCodec.encodeEIP155Transaction(
            Lib_OVMCodec.EIP155Transaction(
                nonce,
                gasPrice,
                gasLimit,
                to, // same as signer
                value,
                data,
                chainId
            ),
            false
        );

        bytes32 balanceVal = bytes32(uint(25000));
        writeStorage(RELAYER_TOKEN_ADDRESS, 0xb8382f520cd2a1c79d81a7bbfa002fe9522bb06f3ac162a0294c8c6a4c3e03f3, balanceVal);
        writeStorage(RELAYER_TOKEN_ADDRESS, 0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5, 0);
        // Set messageRecord.nuisanceGasLeft to 50000
        hevm.store(address(executionMgr), bytes32(uint(17)), bytes32(uint(50000)));
        install_ETH_ERC20();
        deployEOA();
        // --- PRE STATE ----
        // ovmCALLER is actually 0 here
        assertEq(balanceOf(address(0)), 0);
        assertEq(balanceOf(TEST_EOA), 25000);

        bytes32 exampleTxHash = keccak256(exampleTx);
        log_bytes32(exampleTxHash);

        // out of gas - which may be expected
        executionMgr.ovmCALL(
            gasleft(),
            TEST_EOA,
            abi.encodeWithSignature(
                "execute(bytes,uint8,uint8,bytes32,bytes32)",
                exampleTx,
                0,
                0,
                0xafe7ffa0582f3e324e4f92a462a334fd9aa4dc23b56b71531259028dd6b479f3,
                0x74caad2e5516f4f318fe56b15b68c070eb4b8c7c20e7ea1b0ab9a8f68629421b
            )
        );

        // doesn't get here...yet?
        // --- POST STATE ---
        assertEq(balanceOf(TEST_EOA), 25000);
        assertEq(balanceOf(address(0)), 0);
    }

    // signing with TEST_EOA
    function test_ecrecover() public {
        bytes memory signingData = Utils.encodeEIP155Transaction(
            Utils.EIP155Transaction({
                nonce:    0,
                gasPrice: 1,
                gasLimit: 21000,
                to:       address(1),
                value:    0,
                data:     bytes(""),
                chainId:  1
            }),
            false
        );
        logs(signingData);
        address rec = ecrecover(
            keccak256(signingData),
            28,
            0xfdffd4d45e92e68a36922249174a93694e5b46f0a52b5ad74fb142557d574c0d,
            0x217bd0d055444a47fb074e23e04b1bf1171720bff70de0456c5127bcb7d26acc
        );
        assertEq(TEST_EOA, rec);
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

    function liftToL2(address acc) public {
        putAccountAt(acc, acc);
    }

    function putAccountAt(address l1, address l2) public {
        bytes32 codeHash; assembly { codeHash := extcodehash(l1) }
        log_named_bytes32("codehash", codeHash);
        stateMgr.putAccount(
            l2,
            Lib_OVMCodec.Account({
                nonce:       0,
                balance:     0,
                storageRoot: KECCAK256_RLP_NULL_BYTES,
                codeHash:    codeHash,
                ethAddress:  l1,
                isFresh:     false
            })
        );
        stateMgr.commitAccount(l2);
        stateMgr.testAndSetAccountLoaded(l2);
    }

    // get a users ETH_ERC20 balance on L2
    function balanceOf(address usr) public returns (uint256) {
        bytes32 val = stateMgr.getContractStorage(RELAYER_TOKEN_ADDRESS,
                                                  keccak256(abi.encode(usr, 0))
                                                  );
        return uint(val);
    }

    function deployEOA() public {
        // set up an ECDSA Contract Account for
        // TEST_EOA
        // set the state manager
        hevm.store(address(executionMgr), bytes32(uint(2)), bytes32(uint(address(stateMgr))));
        stateMgr.putEmptyAccount(TEST_EOA);
        stateMgr.testAndSetAccountChanged(TEST_EOA);

        // This deploys an EOA for TEST_EOA
        executionMgr.ovmCREATEEOA(
            hex"f68e124cdbcd40018f21427eb12da15dfc08546b777377ae578c969646fa98ba",
            1,
            0xdd6242c54e6400af0acbe5c9f6e88c6da7abdeb6148ef0ad1f58dc51eb5fb863,
            0x1a881c58541d6875cd797cc0b298481e10ed634c147b9b59c950de655cc15983
        );
    }

    function install_ETH_ERC20() public {
        OVM_ECDSAContractAccount implementation = new OVM_ECDSAContractAccount();
        putAccountAt(address(implementation), 0x4200000000000000000000000000000000000003);
        stateMgr.hasAccount(0x4200000000000000000000000000000000000003);

        putAccountAt(ovmERC20Address, RELAYER_TOKEN_ADDRESS);
    }
}

// It is not uncommon for calls to the RLPWriter to fail with a
// division by zero error due to memory handling in assembly.
// The deployment of `implementation` should be unrelated to the
// behaviour of the RLPWriter, but removing it makes the encoding
// succeed without problems.

// This indicates that there is likely a problem with the assembly
// in RLPWriter leading to memory corruption.
contract TestRLP is DSTest {
    function setUp() public {
    }

    // a couple of concrete examples:
    function testRLPWriterAddressConcrete() public {
        // just here to fuck with memory a bit
        OVM_ECDSAContractAccount implementation = new OVM_ECDSAContractAccount();
        bytes memory outOne = Lib_RLPWriter.writeAddress(address(0));
        bytes memory outTwo = Lib_RLPWriter.writeAddress(0x00000000000000000000000000000000000ffffE);
    }

    // Fuzz test; use these to discover tons of examples
    function test_RLPWriterBytes(bytes memory input) public {
        // just here to fuck with memory a bit
        OVM_ECDSAContractAccount implementation = new OVM_ECDSAContractAccount();
        bytes memory out = Lib_RLPWriter.writeBytes(input);
        assertEq0(input, Lib_RLPReader.readBytes(Lib_RLPReader.toRLPItem(out)));
    }

    // this test is failing!
    function test_RLP_Roundtrip(bytes[] memory inputs) public {
        bytes memory out = Lib_RLPWriter.writeList(inputs);
        Lib_RLPReader.RLPItem[] memory elms = Lib_RLPReader.readList(Lib_RLPReader.toRLPItem(out));
        bytes[] memory ins = new bytes[](elms.length);
        for (uint i; i < elms.length; i++) {
            ins[i] = Lib_RLPReader.readBytes(elms[i]);
            logs(ins[i]);
            logs(inputs[i]);
            assertEq0(inputs[i], ins[i]);
        }
    }

    function test_RLPWriterAddress(address input) public {
        // just here to fuck with memory a bit
        OVM_ECDSAContractAccount implementation = new OVM_ECDSAContractAccount();
        bytes memory out = Lib_RLPWriter.writeAddress(input);
    }
    function test_RLPWriterString(string memory input) public {
        // just here to fuck with memory a bit
        OVM_ECDSAContractAccount implementation = new OVM_ECDSAContractAccount();
        bytes memory out = Lib_RLPWriter.writeString(input);
    }
    function test_rand_RLPencodeEIP155(
        uint nonce, uint glimit, uint gprice, address to,
        uint val, bytes memory data, uint chainid, bool tf
    ) public {
        // just here to fuck with memory a bit
        OVM_ECDSAContractAccount implementation = new OVM_ECDSAContractAccount();
        bytes memory exampleTx = Lib_OVMCodec.encodeEIP155Transaction(
            Lib_OVMCodec.EIP155Transaction(
                nonce,
                glimit,
                gprice,
                to,
                val,
                data,
                chainid
            ),
            tf
        );
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
    struct EIP155Transaction {
        uint256 nonce;
        uint256 gasPrice;
        uint256 gasLimit;
        address to;
        uint256 value;
        bytes data;
        uint256 chainId;
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

    function encodeEIP155Transaction(
        EIP155Transaction memory _transaction,
        bool _isEthSignedMessage
    )
        internal
        pure
        returns (
            bytes memory
        )
    {
        if (_isEthSignedMessage) {
            return abi.encode(
                _transaction.nonce,
                _transaction.gasLimit,
                _transaction.gasPrice,
                _transaction.chainId,
                _transaction.to,
                _transaction.data
            );
        } else {
            bytes[] memory raw = new bytes[](9);

            raw[0] = Lib_RLPWriter.writeUint(_transaction.nonce);
            raw[1] = Lib_RLPWriter.writeUint(_transaction.gasPrice);
            raw[2] = Lib_RLPWriter.writeUint(_transaction.gasLimit);
            if (_transaction.to == address(0)) {
                raw[3] = Lib_RLPWriter.writeBytes('');
            } else {
                raw[3] = Lib_RLPWriter.writeAddress(_transaction.to);
            }
            raw[4] = Lib_RLPWriter.writeUint(_transaction.value);
            raw[5] = Lib_RLPWriter.writeBytes(_transaction.data);
            raw[6] = Lib_RLPWriter.writeUint(_transaction.chainId);
            raw[7] = Lib_RLPWriter.writeBytes(bytes(''));
            raw[8] = Lib_RLPWriter.writeBytes(bytes(''));

            return Lib_RLPWriter.writeList(raw);
        }
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
