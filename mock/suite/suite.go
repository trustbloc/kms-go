/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package suite contains mocks for kms+crypto wrapper suite.
package suite

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/mock/wrapper"
	"github.com/trustbloc/kms-go/wrapper/api"
)

// MockSuite mocks api.Suite.
type MockSuite wrapper.MockKMSCrypto

// KMSCrypto mock.
func (m *MockSuite) KMSCrypto() (api.KMSCrypto, error) {
	return (*wrapper.MockKMSCrypto)(m), nil
}

// KeyCreator mock.
func (m *MockSuite) KeyCreator() (api.KeyCreator, error) {
	return (*wrapper.MockKMSCrypto)(m), nil
}

// RawKeyCreator mock.
func (m *MockSuite) RawKeyCreator() (api.RawKeyCreator, error) {
	return (*wrapper.MockKMSCrypto)(m), nil
}

// KMSCryptoSigner mock.
func (m *MockSuite) KMSCryptoSigner() (api.KMSCryptoSigner, error) {
	return (*wrapper.MockKMSCrypto)(m), nil
}

// KMSCryptoVerifier mock.
func (m *MockSuite) KMSCryptoVerifier() (api.KMSCryptoVerifier, error) {
	return (*wrapper.MockKMSCrypto)(m), nil
}

// KMSCryptoMultiSigner mock.
func (m *MockSuite) KMSCryptoMultiSigner() (api.KMSCryptoMultiSigner, error) {
	return (*wrapper.MockKMSCrypto)(m), nil
}

// EncrypterDecrypter mock.
func (m *MockSuite) EncrypterDecrypter() (api.EncrypterDecrypter, error) {
	return (*wrapper.MockKMSCrypto)(m), nil
}

// FixedKeyCrypto mock.
func (m *MockSuite) FixedKeyCrypto(pub *jwk.JWK) (api.FixedKeyCrypto, error) {
	return (*wrapper.MockKMSCrypto)(m).FixedKeyCrypto(pub)
}

// FixedKeySigner mock.
func (m *MockSuite) FixedKeySigner(kid string) (api.FixedKeySigner, error) {
	return (*wrapper.MockKMSCrypto)(m).FixedKeySigner(nil)
}

// FixedKeyMultiSigner mock.
func (m *MockSuite) FixedKeyMultiSigner(kid string) (api.FixedKeyMultiSigner, error) {
	return (*wrapper.MockKMSCrypto)(m).FixedKeyMultiSigner(nil)
}

var _ api.Suite = &MockSuite{}
