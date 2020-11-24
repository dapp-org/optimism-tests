// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.7.4;

pragma experimental ABIEncoderV2;

import { iOVM_ExecutionManager } from "../contracts-v2/contracts/optimistic-ethereum/iOVM/execution/iOVM_ExecutionManager.sol";
import { Lib_AddressResolver } from "../contracts-v2/contracts/optimistic-ethereum/libraries/resolver/Lib_AddressResolver.sol";
import { Lib_Bytes32Utils } from "../contracts-v2/contracts/optimistic-ethereum/libraries/utils/Lib_Bytes32Utils.sol";
import { Lib_BytesUtils } from "../contracts-v2/contracts/optimistic-ethereum/libraries/utils/Lib_BytesUtils.sol";
import { Lib_AddressManager } from "../contracts-v2/contracts/optimistic-ethereum/libraries/resolver/Lib_AddressManager.sol";
import { Lib_OVMCodec } from "../contracts-v2/contracts/optimistic-ethereum/libraries/codec/Lib_OVMCodec.sol";
import { Lib_RLPWriter } from "../contracts-v2/contracts/optimistic-ethereum/libraries/rlp/Lib_RLPWriter.sol";
import { Lib_RLPReader } from "../contracts-v2/contracts/optimistic-ethereum/libraries/rlp/Lib_RLPReader.sol";
import { Lib_BytesUtils } from "../contracts-v2/contracts/optimistic-ethereum/libraries/utils/Lib_BytesUtils.sol";
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

contract StateTransitionerTest is DSTest {
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

        // Set messageRecord.nuisanceGasLeft to 50000
        hevm.store(address(executionMgr), bytes32(uint(17)), bytes32(uint(50000)));

        // set up an ECDSA Contract Account for TEST_EOA
        // set the state manager
        hevm.store(address(executionMgr), bytes32(uint(2)), bytes32(uint(address(stateMgr))));
        stateMgr.putEmptyAccount(TEST_EOA);
        stateMgr.testAndSetAccountChanged(TEST_EOA);

        // install the implementation
        OVM_ECDSAContractAccount implementation = new OVM_ECDSAContractAccount();
        putAccountAt(address(implementation), 0x4200000000000000000000000000000000000003);
        stateMgr.hasAccount(0x4200000000000000000000000000000000000003);

        // deploy EOA for TEST_EOA
        executionMgr.ovmCREATEEOA(
            hex"f68e124cdbcd40018f21427eb12da15dfc08546b777377ae578c969646fa98ba",
            1,
            0xdd6242c54e6400af0acbe5c9f6e88c6da7abdeb6148ef0ad1f58dc51eb5fb863,
            0x1a881c58541d6875cd797cc0b298481e10ed634c147b9b59c950de655cc15983
        );

        // install L2 WETH
        putAccountAt(ovmERC20Address, RELAYER_TOKEN_ADDRESS);
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

    // upgrades the EOA implementation
    function test_upgrade_eoa() public {
        address empty = address(new Empty());
        liftToL2(empty);

        // --- build tx ---

        bytes memory wrappedTx = Lib_OVMCodec.encodeEIP155Transaction(
            Lib_OVMCodec.EIP155Transaction({
                nonce:    1,
                gasPrice: 100,
                gasLimit: 543321,
                to:       TEST_EOA,
                value:    0,
                data:     abi.encodeWithSignature("upgrade(address)", empty),
                chainId:  420
            }),
            false
        );

        // signature generated with:
        // NONCE=1 GAS_PRICE=100 GAS_LIMIT=543321 VALUE=0 CHAIN_ID=420 TO=0xD521C744831cFa3ffe472d9F5F9398c9Ac806203 DATA=0x0900f010000000000000000000000000196d2b8a346ab5d661e74a24840c24754df05d3b ./sign
        uint8 v = 0;
        bytes32 r = 0xf26efebc963441c1333fa42df633bdd0a6a0cfa4d00b0e70986397ff8847a57f;
        bytes32 s = 0x70d9e5db90c7e5af65f50868ef36159449a5542456647d206eebe68fb8dd7a6b;

        // --- upgrade implementation ---

        // grant some eth balances
        setBalance(TEST_EOA, 25000);
        setBalance(address(0), 0);

        executionMgr.run(
            Lib_OVMCodec.Transaction({
                timestamp:     block.timestamp,
                blockNumber:   block.number,
                l1QueueOrigin: Lib_OVMCodec.QueueOrigin.L1TOL2_QUEUE,
                l1TxOrigin:    address(this),
                entrypoint:    TEST_EOA,
                gasLimit:      100000000,
                data: abi.encodeWithSignature(
                    "execute(bytes,uint8,uint8,bytes32,bytes32)",
                    wrappedTx,
                    Lib_OVMCodec.EOASignatureType.EIP155_TRANSACTON,
                    v,
                    r,
                    s
                )
            }),
            address(stateMgr)
        );

        // --- check poststate ---

        hevm.store(address(executionMgr), bytes32(uint(2)), bytes32(uint(address(stateMgr))));
        (bool res, bytes memory data) = executionMgr.ovmCALL(
            uint(-1),
            TEST_EOA,
            abi.encodeWithSignature("getImplementation()")
        );
        require(res, "cannot get impl");
        address impl = abi.decode(data, (address));

        assertEq(impl, empty);
    }

    function test_relayer_steals_tokens() public {
        address counter = address(new Counter());
        liftToL2(counter);

        // --- build tx ---

        bytes memory data = abi.encodeWithSignature("increment(uint256)", 10000);
        bytes memory wrappedTx = Lib_OVMCodec.encodeEIP155Transaction(
            Lib_OVMCodec.EIP155Transaction({
                nonce:    1,
                gasPrice: 1,
                gasLimit: 17000000,
                to:       counter,
                value:    0,
                data:     data,
                chainId:  420
            }),
            false
        );

        // signature generated with:
        // NONCE=1 GAS_PRICE=1 GAS_LIMIT=17000000 VALUE=0 CHAIN_ID=420 TO=0x196d2b8a346ab5d661e74a24840c24754df05d3b DATA=0x7cf5dab00000000000000000000000000000000000000000000000000000000000002710 ./sign
        uint8   v = 0;
        bytes32 r = 0xc946c65c694ac5126f80fefeec1f8277e0e8bedb91bc83e9a20e3843ae0dd33e;
        bytes32 s = 0x648b55e47f0581cf81e59c073f88ae9557227fab1c0bc1aa7d6560323fb34a94;
        assertEq(TEST_EOA, Lib_ECDSAUtils.recover(wrappedTx, false, v, r, s));

        // --- relayer executes tx with insufficient gas ---

        // grant some eth balances
        setBalance(TEST_EOA, 17000000);
        setBalance(address(0), 0);

        uint gasBefore = gasleft();
        (bool res,) = address(executionMgr).call{gas:2000000}(abi.encodeWithSignature(
            "run((uint256,uint256,uint8,address,address,uint256,bytes),address)",
            Lib_OVMCodec.Transaction({
                timestamp:     block.timestamp,
                blockNumber:   block.number,
                l1QueueOrigin: Lib_OVMCodec.QueueOrigin.L1TOL2_QUEUE,
                l1TxOrigin:    address(this),
                entrypoint:    TEST_EOA,
                gasLimit:      100000000,
                data: abi.encodeWithSignature(
                    "execute(bytes,uint8,uint8,bytes32,bytes32)",
                    wrappedTx,
                    Lib_OVMCodec.EOASignatureType.EIP155_TRANSACTON,
                    v,
                    r,
                    s
                )
            }),
            address(stateMgr)
        ));
        uint gasAfter = gasleft();
        emit log_named_uint("gasused", gasBefore - gasAfter);
        emit log_named_uint("profit", 17000000 - (gasBefore - gasAfter));
        require(res, "run failed");

        // the relayer got paid for the gas
        assertEq(balanceOf(address(0)), 17000000);
        assertEq(balanceOf(TEST_EOA), 0);

        // the computation has not been carried out
        assertEq(Counter(counter).count(), 0);
    }

    // NONCE=1 GAS_PRICE=0x346dc5d63886594af4f0d844d013a92a305532617c1bda5119ce075f6fd22 GAS_LIMIT=20000 VALUE=0 CHAIN_ID=420 TO=0xD521C744831cFa3ffe472d9F5F9398c9Ac806203 ./sign
    // demonstrates successful gas overflow in the ECDSAContractAccount
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

        // --- grant the sender some balance ---
        uint balanceVal = 25000;
        setBalance(TEST_EOA, balanceVal);
        setBalance(address(0), 0);

        // --- PRE STATE ----
        // ovmCALLER is actually 0 here
        assertEq(balanceOf(address(0)), 0);
        assertEq(balanceOf(TEST_EOA), 25000);
        assertEq(stateMgr.getAccountNonce(TEST_EOA), 1);

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
        assertEq(stateMgr.getAccountNonce(TEST_EOA), 2);
        assertEq(balanceOf(TEST_EOA), 25000 - 64);
        assertEq(balanceOf(address(0)), 64);
    }

    // demonstrates wrong chainid replaying
    // NONCE=1 GAS_PRICE=1 GAS_LIMIT=21000 VALUE=0 CHAIN_ID=1 TO=0xD521C744831cFa3ffe472d9F5F9398c9Ac806203 ./sign
    function testChainIdReplay() public {
        // This tx has chainid = 1.
        uint256 nonce = 1;
        uint256 gasPrice = 1;
        uint256 gasLimit = 21000;
        address to = 0xD521C744831cFa3ffe472d9F5F9398c9Ac806203;
        uint256 value = 0;
        bytes memory data = "";
        uint256 chainId = 1;
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

        uint balanceVal = 25000;
        setBalance(TEST_EOA, balanceVal);
        setBalance(address(0), 0);

        // --- PRE STATE ----
        // ovmCALLER is actually 0 here
        assertEq(stateMgr.getAccountNonce(TEST_EOA), 1);
        assertEq(balanceOf(address(0)), 0);
        assertEq(balanceOf(0xD521C744831cFa3ffe472d9F5F9398c9Ac806203), 25000);

        executionMgr.ovmCALL(
            gasleft(),
            0xD521C744831cFa3ffe472d9F5F9398c9Ac806203,
            abi.encodeWithSignature(
                "execute(bytes,uint8,uint8,bytes32,bytes32)",
                exampleTx,
                0,
                1,
                0xdd6242c54e6400af0acbe5c9f6e88c6da7abdeb6148ef0ad1f58dc51eb5fb863,
                0x1a881c58541d6875cd797cc0b298481e10ed634c147b9b59c950de655cc15983
            )
        );

        // --- POST STATE ---
        assertEq(stateMgr.getAccountNonce(TEST_EOA), 2);
        assertEq(balanceOf(0xD521C744831cFa3ffe472d9F5F9398c9Ac806203), 25000 - gasLimit);
        assertEq(balanceOf(address(0)), gasLimit);
    }

    // NONCE=1 GAS_PRICE=200 GAS_LIMIT=200 VALUE=0 CHAIN_ID=420 CREATE=1 DATA=0x00 ./sign
    // this test allows a transfer but create will always use more than 200 gas (the gasLimit)
    function test_underflow_gascap() public {
        uint256 nonce = 1;
        uint256 gasPrice = 200;
        uint256 gasLimit = 200;
        address to = 0x0000000000000000000000000000000000000000;
        uint256 value = 0;
        bytes memory data = hex"00";
        uint256 chainId = 420;
        bytes memory exampleTx = Lib_OVMCodec.encodeEIP155Transaction(
            Lib_OVMCodec.EIP155Transaction(
                nonce,
                gasPrice,
                gasLimit,
                to,
                value,
                data,
                chainId
            ),
            false
        );

        uint balanceVal = 25000;
        setBalance(TEST_EOA, balanceVal);
        setBalance(address(0), 0);

        // --- PRE STATE ----
        // ovmCALLER is actually 0 here
        assertEq(stateMgr.getAccountNonce(TEST_EOA), 1);
        assertEq(balanceOf(address(0)), 0);
        assertEq(balanceOf(TEST_EOA), balanceVal);

        bytes32 exampleTxHash = keccak256(exampleTx);
        log_bytes32(exampleTxHash);

        // contract address being deployed
        stateMgr.putEmptyAccount(0x76BB5602C9206F52ee65a09cf1Ba314d31B2aBE6);

        executionMgr.ovmCALL(
            gasleft(),
            TEST_EOA,
            abi.encodeWithSignature(
                "execute(bytes,uint8,uint8,bytes32,bytes32)",
                exampleTx,
                0,
                1,
                0x651988607b17d95473c1611de973844b10fe167a0b822c00aea485cd0a3e3602,
                0x64df71c32cead3b85c7d0c6112ce011622b73d8d5d1f5aaa7c28f40a5d15002e
            )
        );

        // --- POST STATE ---
        assertEq(stateMgr.getAccountNonce(TEST_EOA), 2);
        assertEq(balanceOf(TEST_EOA), 25000);
        assertEq(balanceOf(address(0)), 0);
    }

    // signing with TEST_EOA
    function test_ecrecover() public {
        bytes memory signingData = Lib_OVMCodec.encodeEIP155Transaction(
            Lib_OVMCodec.EIP155Transaction({
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

    function setBalance(address usr, uint balance) internal {
        writeStorage(RELAYER_TOKEN_ADDRESS, keccak256(abi.encode(usr, 0)), bytes32(balance));
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

    function testAddressInverse() public {
      address addr = address(1);
        assertEq(addr,  Lib_Bytes32Utils.toAddress(Lib_Bytes32Utils.fromAddress(addr)));
    }

    function testSlice() public {
        // just here to fuck with memory a bit
        OVM_ECDSAContractAccount implementation = new OVM_ECDSAContractAccount();
        assertEq0(hex'',  Lib_BytesUtils.slice(hex'', 0, 0));
    }

    function test_RLP_Roundtrip(bytes[] memory inputs) public {
        if (inputs.length > 32) return;
        bytes[] memory ins = new bytes[](inputs.length);
        for (uint i; i < inputs.length; i++) {
            ins[i] = Lib_RLPWriter.writeBytes(inputs[i]);
        }
        bytes memory out = Lib_RLPWriter.writeList(ins);
        Lib_RLPReader.RLPItem[] memory decoded = Lib_RLPReader.readList(out);
        for (uint i; i < decoded.length; i++) {
            bytes memory dec = Lib_RLPReader.readBytes(decoded[i]);
            logs(inputs[i]);
            logs(dec);
            assertEq0(inputs[i], dec);
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

contract TestBytesUtils is DSTest {
    function setUp() public {
    }

    function test_concat_concrete() public {
        test_concat(hex"1234", hex"5678");
    }
    function test_concat(bytes memory a, bytes memory b) public {
        OVM_ECDSAContractAccount implementation = new OVM_ECDSAContractAccount();
        // you can actually just use `abi.encodePacked` to concat bytestrings...
        uint startGas = gasleft();
        bytes memory encPak = abi.encodePacked(a, b);
        uint endGas = gasleft();
        emit log_named_uint("gas for abi.encodePacked", startGas - endGas);

        startGas = gasleft();
        bytes memory custom = Lib_BytesUtils.concat(a, b);
        endGas = gasleft();
        emit log_named_uint("gas for custom built", startGas - endGas);
        assertEq0(encPak, custom);
    }

    // gets stuck in an infinite loop and
    // runs out of gas even with 12.5M gas given.
    function test_slic_concrete() public {
        bytes memory custom = Lib_BytesUtils.slice(hex"", 1);
        logs(custom);
    }

    function test_slice(bytes calldata a, uint8 start) public {
        if (start >= a.length) return;
        OVM_ECDSAContractAccount implementation = new OVM_ECDSAContractAccount();
        // we now have slice technology in solidity
        uint startGas = gasleft();
        bytes memory custom = Lib_BytesUtils.slice(a, start);
        uint endGas = gasleft();
        emit log_named_uint("gas for custom built", startGas - endGas);

        startGas = gasleft();
        bytes memory encPak = abi.encodePacked(bytes(a[start:]));
        endGas = gasleft();
        emit log_named_uint("gas for abi.encodePacked", startGas - endGas);
        assertEq0(encPak, custom);

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

contract Counter {
    event Hi(uint n);
    uint public count = 0;

    function increment(uint n) external {
        uint gasBefore = gasleft();
        for (uint i = 0; i < n; i++) {
            count = count + 1;
        }
        uint gasAfter = gasleft();
        emit Hi(gasBefore - gasAfter);
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
