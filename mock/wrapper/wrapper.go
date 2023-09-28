/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package wrapper contains mocks for kms+crypto wrapper APIs.
package wrapper

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/spi/kms"
	wrapperapi "github.com/trustbloc/kms-go/wrapper/api"
)

// MockKMSCrypto mocks wrapper.KMSCrypto.
type MockKMSCrypto struct {
	CreateVal         *jwk.JWK
	CreateRawKID      string
	CreateRawVal      interface{}
	CreateErr         error
	SignVal           []byte
	SignErr           error
	VerifyErr         error
	FixedKeyCryptoVal *MockFixedKeyCrypto
	FixedKeyCryptoErr error
	EncryptVal        []byte
	EncryptNonce      []byte
	EncryptErr        error
	DecryptVal        []byte
	DecryptErr        error
}

// Create mock.
func (m *MockKMSCrypto) Create(keyType kms.KeyType) (*jwk.JWK, error) {
	return m.CreateVal, m.CreateErr
}

// CreateRaw mock.
func (m *MockKMSCrypto) CreateRaw(keyType kms.KeyType) (string, interface{}, error) {
	return m.CreateRawKID, m.CreateRawVal, m.CreateErr
}

// Sign mock.
func (m *MockKMSCrypto) Sign(msg []byte, pub *jwk.JWK) ([]byte, error) {
	return m.SignVal, m.SignErr
}

// SignMulti mock.
func (m *MockKMSCrypto) SignMulti(msgs [][]byte, pub *jwk.JWK) ([]byte, error) {
	return m.SignVal, m.SignErr
}

// Verify mock.
func (m *MockKMSCrypto) Verify(sig, msg []byte, pub *jwk.JWK) error {
	return m.VerifyErr
}

// Encrypt mock.
func (m *MockKMSCrypto) Encrypt(msg, aad []byte, kid string) (cipher, nonce []byte, err error) {
	return m.EncryptVal, m.EncryptNonce, m.EncryptErr
}

// Decrypt mock.
func (m *MockKMSCrypto) Decrypt(cipher, aad, nonce []byte, kid string) (msg []byte, err error) {
	return m.DecryptVal, m.DecryptErr
}

// FixedKeyCrypto mock.
func (m *MockKMSCrypto) FixedKeyCrypto(pub *jwk.JWK) (wrapperapi.FixedKeyCrypto, error) {
	return makeMockFixedKey(m)
}

// FixedKeySigner mock.
func (m *MockKMSCrypto) FixedKeySigner(pub *jwk.JWK) (wrapperapi.FixedKeySigner, error) {
	return makeMockFixedKey(m)
}

// FixedMultiSignerGivenKID mock.
func (m *MockKMSCrypto) FixedMultiSignerGivenKID(kid string) (wrapperapi.FixedKeyMultiSigner, error) {
	return makeMockFixedKey(m)
}

// FixedKeyMultiSigner mock.
func (m *MockKMSCrypto) FixedKeyMultiSigner(pub *jwk.JWK) (wrapperapi.FixedKeyMultiSigner, error) {
	return makeMockFixedKey(m)
}

func makeMockFixedKey(m *MockKMSCrypto) (*MockFixedKeyCrypto, error) {
	if m.FixedKeyCryptoVal != nil || m.FixedKeyCryptoErr != nil {
		return m.FixedKeyCryptoVal, m.FixedKeyCryptoErr
	}

	fkc := &MockFixedKeyCrypto{
		SignErr:   m.SignErr,
		VerifyErr: m.VerifyErr,
	}

	return fkc, nil
}

// MockFixedKeyCrypto mocks kmscrypto.FixedKeyCrypto.
type MockFixedKeyCrypto struct {
	SignVal   []byte
	SignErr   error
	VerifyErr error
}

// Sign mock.
func (m *MockFixedKeyCrypto) Sign(msg []byte) ([]byte, error) {
	return m.SignVal, m.SignErr
}

// SignMulti mock.
func (m *MockFixedKeyCrypto) SignMulti(msgs [][]byte) ([]byte, error) {
	return m.SignVal, m.SignErr
}

// Verify mock.
func (m *MockFixedKeyCrypto) Verify(sig, msg []byte) error {
	return m.VerifyErr
}

var _ wrapperapi.KMSCryptoMultiSigner = &MockKMSCrypto{}

var _ wrapperapi.KMSCrypto = &MockKMSCrypto{}
