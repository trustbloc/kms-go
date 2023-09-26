/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package websuite provides a wrapper.Suite implemented using web kms and web crypto clients.
package websuite

import (
	"net/http"

	webcrypto "github.com/trustbloc/kms-go/crypto/webkms"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/kms/webkms"
	wrapperapi "github.com/trustbloc/kms-go/wrapper/api"
)

// NewWebCryptoSuite initializes an api.Suite using web kms and crypto
// clients, supporting all Suite APIs.
func NewWebCryptoSuite(endpoint string, httpClient *http.Client) wrapperapi.Suite {
	km := webkms.New(endpoint, httpClient)
	cr := webcrypto.New(endpoint, httpClient)

	return &suite{
		km: km,
		cr: cr,
	}
}

type suite struct {
	km *webkms.RemoteKMS
	cr *webcrypto.RemoteCrypto
}

func (s *suite) KMSCryptoVerifier() (wrapperapi.KMSCryptoVerifier, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}

func (s *suite) KeyCreator() (wrapperapi.KeyCreator, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}

func (s *suite) KMSCrypto() (wrapperapi.KMSCrypto, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}

func (s *suite) FixedKeyCrypto(pub *jwk.JWK) (wrapperapi.FixedKeyCrypto, error) {
	return makeFixedKey(pub.KeyID, s.km, s.cr)
}

func (s *suite) RawKeyCreator() (wrapperapi.RawKeyCreator, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}

func (s *suite) KMSCryptoSigner() (wrapperapi.KMSCryptoSigner, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}

func (s *suite) FixedKeySigner(kid string) (wrapperapi.FixedKeySigner, error) {
	return makeFixedKey(kid, s.km, s.cr)
}

func (s *suite) KMSCryptoMultiSigner() (wrapperapi.KMSCryptoMultiSigner, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}

func (s *suite) FixedKeyMultiSigner(kid string) (wrapperapi.FixedKeyMultiSigner, error) {
	return makeFixedKey(kid, s.km, s.cr)
}

func (s *suite) EncrypterDecrypter() (wrapperapi.EncrypterDecrypter, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}
