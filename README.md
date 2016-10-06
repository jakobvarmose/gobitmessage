# GoBitmessage

This is not a full Bitmessage client but will hopefully become one.

The example code only connects to 127.0.0.1:8444, so make sure you have PyBitmessage or another client running. When connected, it will download all objects and decrypt all messages sent to [chan] general.

##How to run the example

```
go get github.com/jakobvarmose/gobitmessage
cd $GOPATH/src/github.com/jakobvarmose/gobitmessage
make
bitmessage/bitmessage
```
