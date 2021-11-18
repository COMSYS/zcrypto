// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "strconv"

type Alert uint8

const (
	// Alert level
	alertLevelWarning = 1
	alertLevelError   = 2
)

const (
	alertCloseNotify            Alert = 0
	alertUnexpectedMessage      Alert = 10
	alertBadRecordMAC           Alert = 20
	alertDecryptionFailed       Alert = 21
	alertRecordOverflow         Alert = 22
	alertDecompressionFailure   Alert = 30
	alertHandshakeFailure       Alert = 40
	alertBadCertificate         Alert = 42
	alertUnsupportedCertificate Alert = 43
	alertCertificateRevoked     Alert = 44
	alertCertificateExpired     Alert = 45
	alertCertificateUnknown     Alert = 46
	alertIllegalParameter       Alert = 47
	alertUnknownCA              Alert = 48
	alertAccessDenied           Alert = 49
	alertDecodeError            Alert = 50
	alertDecryptError           Alert = 51
	alertProtocolVersion        Alert = 70
	alertInsufficientSecurity   Alert = 71
	alertInternalError          Alert = 80
	alertUserCanceled           Alert = 90
	alertNoRenegotiation        Alert = 100
)

var alertText = map[Alert]string{
	alertCloseNotify:            "close notify",
	alertUnexpectedMessage:      "unexpected message",
	alertBadRecordMAC:           "bad record MAC",
	alertDecryptionFailed:       "decryption failed",
	alertRecordOverflow:         "record overflow",
	alertDecompressionFailure:   "decompression failure",
	alertHandshakeFailure:       "handshake failure",
	alertBadCertificate:         "bad certificate",
	alertUnsupportedCertificate: "unsupported certificate",
	alertCertificateRevoked:     "revoked certificate",
	alertCertificateExpired:     "expired certificate",
	alertCertificateUnknown:     "unknown certificate",
	alertIllegalParameter:       "illegal parameter",
	alertUnknownCA:              "unknown certificate authority",
	alertAccessDenied:           "access denied",
	alertDecodeError:            "error decoding message",
	alertDecryptError:           "error decrypting message",
	alertProtocolVersion:        "protocol version not supported",
	alertInsufficientSecurity:   "insufficient security level",
	alertInternalError:          "internal error",
	alertUserCanceled:           "user canceled",
	alertNoRenegotiation:        "no renegotiation",
}

func (e Alert) String() string {
	s, ok := alertText[e]
	if ok {
		return s
	}
	return "alert(" + strconv.Itoa(int(e)) + ")"
}

func (e Alert) Error() string {
	return e.String()
}
