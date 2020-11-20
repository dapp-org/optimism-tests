contract ERC20Setup {
  // Bytecode from yarn all:ovm 
  bytes constant public ERC20_OVM_BYTECODE = 
  hex"60806040523480156100195760008061001661001f565b50505b5061008d565b632a2a7adb598160e01b8152600481016020815285602082015260005b8681101561005a57808601518160408401015260208101905061003c565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6112878061009c6000396000f3fe608060405234801561001957600080610016611024565b50505b50600436106100bd5760003560e01c8063313ce5671161007a578063313ce567146104735780635c6581651461049757806370a082311461051857806395d89b4114610579578063a9059cbb146105fc578063dd62ed3e1461066b576100bd565b806306fdde03146100cb578063095ea7b31461014e57806318160ddd146101bd57806319f37f78146101db57806323b872dd1461038357806327e235e314610412575b6000806100c8611024565b50505b6100d36106ec565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156101135780820151818401526020810190506100f8565b50505050905090810190601f1680156101405780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6101a36004803603604081101561016d5760008061016a611024565b50505b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506107a6565b604051808215151515815260200191505060405180910390f35b6101c56108b1565b6040518082815260200191505060405180910390f35b610381600480360360808110156101fa576000806101f7611024565b50505b81019080803590602001909291908035906020019064010000000081111561022a57600080610227611024565b50505b82018360208201111561024557600080610242611024565b50505b803590602001918460018302840111640100000000831117156102705760008061026d611024565b50505b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290803560ff169060200190929190803590602001906401000000008111156102e9576000806102e6611024565b50505b82018360208201111561030457600080610301611024565b50505b8035906020019184600183028401116401000000008311171561032f5760008061032c611024565b50505b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505091929192905050506108be565b005b6103f8600480360360608110156103a25760008061039f611024565b50505b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803590602001909291905050506109a0565b604051808215151515815260200191505060405180910390f35b61045d600480360360208110156104315760008061042e611024565b50505b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610c8c565b6040518082815260200191505060405180910390f35b61047b610cab565b604051808260ff1660ff16815260200191505060405180910390f35b610502600480360360408110156104b6576000806104b3611024565b50505b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610cc5565b6040518082815260200191505060405180910390f35b6105636004803603602081101561053757600080610534611024565b50505b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610cf1565b6040518082815260200191505060405180910390f35b610581610d40565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156105c15780820151818401526020810190506105a6565b50505050905090810190601f1680156105ee5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6106516004803603604081101561061b57600080610618611024565b50505b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050610dfa565b604051808215151515815260200191505060405180910390f35b6106d66004803603604081101561068a57600080610687611024565b50505b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610f96565b6040518082815260200191505060405180910390f35b6002806106f7611092565b600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280610732611092565b6001816001161561010002031660029004801561079e5780601f1061076c57610100808361075e611092565b04028352916020019161079e565b820191906000526020600020905b81610783611092565b8152906001019060200180831161077a57829003601f168201915b505050505081565b600081600160005a6107b66110f5565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190610837611152565b5050508273ffffffffffffffffffffffffffffffffffffffff165a61085a6110f5565b73ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905092915050565b60056108bb611092565b81565b600060056108ca611092565b146108dd576000806108da611024565b50505b836000805a6108ea6110f5565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819061092e611152565b505050836005819061093e611152565b50505082600290805190602001906109579291906111b7565b5081600360006101000a8161096a611092565b8160ff021916908360ff16021790610980611152565b50505080600490805190602001906109999291906111b7565b5050505050565b600080600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005a6109ed6110f5565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020610a2f611092565b9050826000808773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020610a78611092565b10158015610a865750828110155b610a9857600080610a95611024565b50505b826000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282610ae3611092565b019250508190610af1611152565b505050826000808773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282610b3f611092565b039250508190610b4d611152565b5050507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff811015610c1b5782600160008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005a610bc36110f5565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282610c09611092565b039250508190610c17611152565b5050505b8373ffffffffffffffffffffffffffffffffffffffff168573ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef856040518082815260200191505060405180910390a360019150509392505050565b6000602052806000526040600020600091509050610ca8611092565b81565b6003600090610cb8611092565b906101000a900460ff1681565b600160205281600052604060002060205280600052604060002060009150915050610cee611092565b81565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020610d39611092565b9050919050565b600480610d4b611092565b600181600116156101000203166002900480601f01602080910402602001604051908101604052809291908181526020018280610d86611092565b60018160011615610100020316600290048015610df25780601f10610dc0576101008083610db2611092565b040283529160200191610df2565b820191906000526020600020905b81610dd7611092565b81529060010190602001808311610dce57829003601f168201915b505050505081565b6000816000805a610e096110f5565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020610e4b611092565b1015610e5f57600080610e5c611024565b50505b816000805a610e6c6110f5565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282610eb2611092565b039250508190610ec0611152565b505050816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282610f0e611092565b019250508190610f1c611152565b5050508273ffffffffffffffffffffffffffffffffffffffff165a610f3f6110f5565b73ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a36001905092915050565b6000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002061101c611092565b905092915050565b632a2a7adb598160e01b8152600481016020815285602082015260005b8681101561105f578086015181604084010152602081019050611041565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6303daa959598160e01b8152836004820152602081602483336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b8051935060005b60408110156110f0576000818301526020810190506110d6565b505050565b6373509064598160e01b8152602081600483336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b8051935060005b604081101561114d57600081830152602081019050611133565b505050565b6322bd64c0598160e01b8152836004820152846024820152600081604483336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b60005b60408110156111b257600081830152602081019050611198565b505050565b82806111c1611092565b600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061120857805160ff19168380011785611201611152565b5050611248565b82800160010185611217611152565b50508215611248579182015b8281111561124757825182611236611152565b505091602001919060010190611223565b5b5090506112559190611259565b5090565b61128491905b8082111561128057600081600090611275611152565b50505060010161125f565b5090565b9056";
  function write(bytes memory _code) public returns (address target) {
    assembly {
      target := create(0, add(_code, 0x20), mload(_code))
    }
  }

  function deployTokenContract() public returns (address) {
    return write(ERC20_OVM_BYTECODE);
  }
}