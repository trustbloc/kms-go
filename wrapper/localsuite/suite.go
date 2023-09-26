/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package localsuite

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	wrapperapi "github.com/trustbloc/kms-go/wrapper/api"
)

type suiteImpl struct {
	kms    keyManager
	crypto allCrypto
}

func (s *suiteImpl) KeyCreator() (wrapperapi.KeyCreator, error) {
	return newKeyCreator(s.kms), nil
}

func (s *suiteImpl) RawKeyCreator() (wrapperapi.RawKeyCreator, error) {
	return newKeyCreator(s.kms), nil
}

func (s *suiteImpl) KMSCrypto() (wrapperapi.KMSCrypto, error) {
	return newKMSCrypto(s.kms, s.crypto), nil
}

func (s *suiteImpl) KMSCryptoSigner() (wrapperapi.KMSCryptoSigner, error) {
	return newKMSCryptoSigner(s.kms, s.crypto), nil
}

func (s *suiteImpl) KMSCryptoMultiSigner() (wrapperapi.KMSCryptoMultiSigner, error) {
	return newKMSCryptoMultiSigner(s.kms, s.crypto), nil
}

func (s *suiteImpl) KMSCryptoVerifier() (wrapperapi.KMSCryptoVerifier, error) {
	return newKMSCrypto(s.kms, s.crypto), nil
}

func (s *suiteImpl) EncrypterDecrypter() (wrapperapi.EncrypterDecrypter, error) {
	return newEncrypterDecrypter(s.kms, s.crypto), nil
}

func (s *suiteImpl) FixedKeyCrypto(pub *jwk.JWK) (wrapperapi.FixedKeyCrypto, error) {
	return makeFixedKeyCrypto(s.kms, s.crypto, pub)
}

func (s *suiteImpl) FixedKeySigner(kid string) (wrapperapi.FixedKeySigner, error) {
	return makeFixedKeySigner(s.kms, s.crypto, kid)
}

func (s *suiteImpl) FixedKeyMultiSigner(kid string) (wrapperapi.FixedKeyMultiSigner, error) {
	return getFixedMultiSigner(s.kms, s.crypto, kid)
}
