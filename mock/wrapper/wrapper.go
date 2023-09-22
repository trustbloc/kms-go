/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package wrapper contains mocks for kms+crypto wrapper APIs.
package wrapper

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper"
)

// MockKMSCrypto mocks wrapper.KMSCrypto.
type MockKMSCrypto struct {
	CreateVal         *jwk.JWK
	CreateErr         error
	SignVal           []byte
	SignErr           error
	VerifyErr         error
	FixedKeyCryptoVal *MockFixedKeyCrypto
	FixedKeyCryptoErr error
}

// Create mock.
func (m *MockKMSCrypto) Create(keyType kms.KeyType) (*jwk.JWK, error) {
	return m.CreateVal, m.CreateErr
}

// Sign mock.
func (m *MockKMSCrypto) Sign(msg []byte, pub *jwk.JWK) ([]byte, error) {
	return m.SignVal, m.SignErr
}

// Verify mock.
func (m *MockKMSCrypto) Verify(sig, msg []byte, pub *jwk.JWK) error {
	return m.VerifyErr
}

// FixedKeyCrypto mock.
func (m *MockKMSCrypto) FixedKeyCrypto(pub *jwk.JWK) (wrapper.FixedKeyCrypto, error) {
	return m.FixedKeyCryptoVal, m.FixedKeyCryptoErr
}

// FixedKeySigner mock.
func (m *MockKMSCrypto) FixedKeySigner(pub *jwk.JWK) (wrapper.FixedKeySigner, error) {
	return m.FixedKeyCryptoVal, m.FixedKeyCryptoErr
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

// Verify mock.
func (m *MockFixedKeyCrypto) Verify(sig, msg []byte) error {
	return m.VerifyErr
}

var _ wrapper.KMSCrypto = &MockKMSCrypto{}
