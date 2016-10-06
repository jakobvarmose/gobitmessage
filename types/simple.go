package types

import (
	"crypto/sha256"
	"strings"
)

type Simple struct {
	Subject      string
	IsReply      bool
	Body         string
	Comment      string
	ParentHashes [][]byte
}

func (s *Simple) Unmarshal(contents []byte) {
	text := string(contents)
	subject := text[8 : 8+strings.Index(text[8:], "\n")]
	if len(subject) >= 4 && subject[:4] == "Re: " {
		s.Subject = subject[4:]
		s.IsReply = true
	} else {
		s.Subject = subject
		s.IsReply = false
	}
	body := text[strings.Index(text, "\nBody:")+6:]
	s.Body = body
	sep := "\n------------------------------------------------------\n"

	ts := strings.Split(body, sep)
	var hashes [][]byte
	hashes = append(hashes, nil)
	for i := len(ts) - 1; i >= 0; i-- {
		h := sha256.New()
		h.Write(hashes[len(hashes)-1])
		h.Write([]byte(ts[i]))
		hashes = append(hashes, h.Sum(nil))
	}
	s.ParentHashes = hashes

	i := strings.Index(body, sep)
	if i >= 0 {
		body = body[:i]
	}
	body = strings.Trim(body, "\n")
	for {
		b := strings.LastIndex(body, "\n")
		if b == -1 {
			break
		}
		if strings.LastIndex(body, "\n> ") != b {
			break
		}
		body = body[:b]
	}
	body = strings.Trim(body, "\n")
	s.Comment = body
}
