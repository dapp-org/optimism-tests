# Optimism ECDSAContractAccount Tests

This repo contains the tests written as part of the [`dapp.org`](https://dapp.org.uk) audit of the
OVM `ECDSAContractAccount` smart wallet.

To run the tests you will need to [install nix](https://nixos.org/download.html), you can then enter
a reproducible dev environment by running `nix-shell` from the repo root.

From within the nix shell you can use
[`dapp`](https://github.com/dapphub/dapptools/tree/master/src/dapp) to run the tests:

```
dapp test  # run tests
dapp debug # interactively debug a test
```
