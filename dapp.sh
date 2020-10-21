if [ `uname` == Darwin ]; then
    dapp --use ./solc-macos-0.7.4 $*
else
    dapp --use ./solc-linux-0.7.4 $*
fi
