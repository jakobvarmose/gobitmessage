all: bitmessage/bitmessage

bitmessage/bitmessage: deps
	cd bitmessage && go build

deps:
	go get golang.org/x/crypto/ripemd160
	go get github.com/Sirupsen/logrus
	go get github.com/ethereum/go-ethereum/crypto/secp256k1

clean:
	rm bitmessage/bitmessage || true

.PHONY: clean
