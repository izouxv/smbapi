package smb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	"github/izouxv/smbapi/smb/encoder"
)

func (s *session) RPC(request interface{}, responce interface{}) (err error) {
	rw := bufio.NewReadWriter(bufio.NewReader(s.conn), bufio.NewWriter(s.conn))

	buf, err := encoder.Marshal(request)
	if err != nil {
		s.Debug("", err)
		return err
	}
	err = s.Send(buf, rw)

	if err != nil {
		return err
	}

	data, _, err := s.Recv(rw)
	if err != nil {
		return err
	}

	s.Debug("Unmarshalling SessionSetup1 response", nil)
	if err = encoder.Unmarshal(data, responce); err != nil {
		s.Debug("Raw:\n"+hex.Dump(data), err)
		return
	}
	return err
}

func (s *session) Send(buf []byte, rw *bufio.ReadWriter) (err error) {
	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(buf))); err != nil {
		s.Debug("", err)
		return
	}

	if _, err = rw.Write(append(b.Bytes(), buf...)); err != nil {
		s.Debug("", err)
		return
	}
	return rw.Flush()
}

func (s *session) Recv(rw *bufio.ReadWriter) (data []byte, ver string, err error) {
	var size uint32
	if err = binary.Read(rw, binary.BigEndian, &size); err != nil {
		s.Debug("", err)
		return
	}
	if size > 0x00FFFFFF {
		return nil, "", errors.New("Invalid NetBIOS Session message")
	}

	data = make([]byte, size)
	l, err := io.ReadFull(rw, data)
	if err != nil {
		s.Debug("", err)
		return nil, "", err
	}
	if uint32(l) != size {
		return nil, "", errors.New("Message size invalid")
	}

	protID := data[0:4]
	switch string(protID) {
	default:
		return nil, "", ErrHeaderSmb1 // errors.New("Protocol Not Implemented")
	case ProtocolSmb2:
		return data, string(protID), nil
	case ProtocolSmb:
		return data, string(protID), nil
	}
}

// func (s *Session) _______sendLegacy(req interface{}) (res []byte, err error) {
// 	buf, err := encoder.Marshal(req)
// 	if err != nil {
// 		s.Debug("", err)
// 		return nil, err
// 	}

// 	b := new(bytes.Buffer)
// 	if err = binary.Write(b, binary.BigEndian, uint32(len(buf))); err != nil {
// 		s.Debug("", err)
// 		return
// 	}

// 	rw := bufio.NewReadWriter(bufio.NewReader(s.conn), bufio.NewWriter(s.conn))
// 	if _, err = rw.Write(append(b.Bytes(), buf...)); err != nil {
// 		s.Debug("", err)
// 		return
// 	}
// 	rw.Flush()

// 	var size uint32
// 	if err = binary.Read(rw, binary.BigEndian, &size); err != nil {
// 		s.Debug("", err)
// 		return
// 	}
// 	if size > 0x00FFFFFF {
// 		return nil, errors.New("Invalid NetBIOS Session message")
// 	}

// 	data := make([]byte, size)
// 	l, err := io.ReadFull(rw, data)
// 	if err != nil {
// 		s.Debug("", err)
// 		return nil, err
// 	}
// 	if uint32(l) != size {
// 		return nil, errors.New("Message size invalid")
// 	}

// 	protID := data[0:4]
// 	switch string(protID) {
// 	default:
// 		return nil, errors.New("Protocol Not Implemented")
// 	case ProtocolSmb2:
// 	}

// 	return data, nil
// }
