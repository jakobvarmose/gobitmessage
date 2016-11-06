package main

import (
	"crypto/sha512"
	"math/rand"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/jakobvarmose/gobitmessage/crypt"
	"github.com/jakobvarmose/gobitmessage/objectstorage"
	"github.com/jakobvarmose/gobitmessage/packets"
	"github.com/jakobvarmose/gobitmessage/types"
)

type Conn struct {
	address string
	Hashes  map[string]bool
	Conn    net.Conn
}

func main() {
	combo := crypt.DeterministicPrivateCombo("general")
	objs := objectstorage.NewMap()
	clientNonce := uint64(rand.Int63())
	c := new(Conn)
	c.Hashes = make(map[string]bool)
	address := "127.0.0.1:8444"

	for {
		for c.Conn == nil {
			logrus.Infof("Connecting to %s", address)
			conn, err := net.Dial("tcp", address)
			if err != nil {
				panic(err)
			}
			c.Conn = conn
			version := packets.Version{
				Version:   3,
				Services:  1,
				Timestamp: time.Now().Unix(),

				SrcServices: 1,
				SrcIP:       make([]byte, 16),
				SrcPort:     0,

				DstServices: 1,
				DstIP:       make([]byte, 16),
				DstPort:     0,

				Nonce:     clientNonce,
				UserAgent: "/gobitmessage:0.1/",
				Streams:   []uint64{1},
			}
			packets.Write(conn, packets.Packet{"version", version.Marshal()})
		}
		p, err := packets.Read(c.Conn)
		if err != nil {
			c.Conn = nil
			continue
		}
		if p.Command == "verack" {
			logrus.Infof("Verack")
		} else if p.Command == "version" {
			version := new(packets.Version)
			err := version.Unmarshal(p.Payload)
			if err != nil {
				return
			}
			if version.Nonce == clientNonce {
				return
			}
			logrus.Infof("Version %s\n", version.UserAgent)
			packets.Write(c.Conn, packets.Packet{"verack", nil})
		} else if p.Command == "inv" {
			var inv packets.Collection
			inv.Unmarshal(p.Payload)
			var getdata packets.Collection
			for _, hash := range inv {
				logrus.Infof("Inv %x", hash)
				c.Hashes[hash] = true
				if ok, _ := objs.Exists([]byte(hash)); !ok {
					getdata = append(getdata, hash)
					if len(getdata) == 3000 {
						break
					}
				}
			}
			if len(getdata) != 0 {
				packets.Write(c.Conn, packets.Packet{
					packets.Command_Getdata,
					getdata.Marshal(),
				})
			}
		} else if p.Command == "addr" {
		} else if p.Command == "getdata" {
			var getdata packets.Collection
			getdata.Unmarshal(p.Payload)
			for _, hash := range getdata {
				object, err := objs.Get([]byte(hash))
				if err != nil {
					continue
				}
				packets.Write(c.Conn, packets.Packet{
					packets.Command_Object,
					object,
				})
			}
		} else if p.Command == "object" {
			//TODO verify data before storing
			h1 := sha512.Sum512(p.Payload)
			h2 := sha512.Sum512(h1[:])
			//logrus.Infof("Obj %x", h2[:32])
			objs.Put(h2[:32], p.Payload)
			object, err := types.UnmarshalObject(p.Payload)
			if err != nil {
				logrus.Error(err.Error())
			}
			if object.Header.Type == types.Type_Msg || true {
				decrypted, _ := combo.EncryptionKey.Decrypt(object.Payload)
				if decrypted != nil {
					var msg types.Message
					msg.Unmarshal(decrypted)
					var simple types.Simple
					simple.Unmarshal(msg.Contents)
					address := crypt.Address{msg.Version, msg.Stream, msg.Combo.Ripe()}
					logrus.Infof("%s: %s", address.String(), simple.Subject)
				}
			}
		}
	}
}
