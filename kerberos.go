package kerberos

// #cgo LDFLAGS: -lsasl2
/*
#include <sasl/sasl.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"unsafe"
)

type SaramaKerberosSASL struct {
	serviceName string
	keytab      string
	principal   string
}

func NewSaramaKerberosSASL(serviceName, keytab, principal string) *SaramaKerberosSASL {
	return &SaramaKerberosSASL{
		serviceName: serviceName,
		keytab:      keytab,
		principal:   principal,
	}
}

func (s *SaramaKerberosSASL) Authorize(conn net.Conn, addr string) error {
	serviceHost := strings.Split(addr, ":")[0]
	cmd := exec.Command(
		"kinit",
		"-S",
		fmt.Sprintf("%s/%s", s.serviceName, serviceHost),
		"-k",
		"-t",
		s.keytab,
		s.principal)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("kinit start: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("kinit wait: %v", err)
	}

	if errorCode := C.sasl_client_init(nil); errorCode != C.SASL_OK {
		return fmt.Errorf("sasl_client_init error != OK: %v", errorCode)
	}
	var context *C.sasl_conn_t
	// defer C.sasl_dispose(&context) ???
	serviceName := C.CString(s.serviceName)
	defer C.free(unsafe.Pointer(serviceName))
	host := C.CString(serviceHost)
	defer C.free(unsafe.Pointer(host))

	if errorCode := C.sasl_client_new(serviceName, host, nil, nil, nil, C.uint(0), &context); errorCode != C.SASL_OK {
		return fmt.Errorf("sasl_client_new cannot establish new context: %v", errorCode)
	}

	var out *C.char
	var outlen C.uint
	mech := C.CString("GSSAPI")
	defer C.free(unsafe.Pointer(mech))

	errorCode := C.sasl_client_start(context, mech, nil, &out, &outlen, nil)
	defer C.free(unsafe.Pointer(out))

	requestToken := C.GoBytes(unsafe.Pointer(out), C.int(outlen))
	err := s.sendToken(conn, requestToken)
	if err != nil {
		return errors.New("Connection closed by service")
	}

	for errorCode == C.SASL_CONTINUE {
		responseToken, err := s.recvToken(conn)
		if err != nil {
			return errors.New("Connection closed by service")
		}

		errorCode = C.sasl_client_step(context, (*C.char)(unsafe.Pointer(&responseToken[0])), C.uint(len(responseToken)), nil, &out, &outlen)
		requestToken := C.GoBytes(unsafe.Pointer(out), C.int(outlen))
		err = s.sendToken(conn, requestToken)
		if err != nil {
			return errors.New("Connection closed by service")
		}
	}

	if errorCode != C.SASL_OK {
		return errors.New("Authentication handshake was not completed")
	}

	return nil
}

func (s *SaramaKerberosSASL) sendToken(conn net.Conn, buf []byte) error {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(buf)))
	_, err := conn.Write(b)
	if err != nil {
		return err
	}
	conn.Write(buf)
	if err != nil {
		return err
	}
	return nil
}

func (s *SaramaKerberosSASL) recvToken(conn net.Conn) ([]byte, error) {
	b := make([]byte, 4)
	_, err := conn.Read(b)
	if err != nil {
		return b, err
	}

	size := binary.BigEndian.Uint32(b)
	buf := make([]byte, size)
	_, err = conn.Read(buf)

	return buf, err
}
