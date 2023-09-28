/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"errors"

	"github.com/trustbloc/kms-go/doc/jose/jwk"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
)

// Suite provides a suite of kms+crypto functions.
//
// Each suite method returns an implementation of a particular kms+crypto API,
// or ErrNotSupported if the given Suite does not support the requested API.
type Suite interface {
	KeyCreator() (KeyCreator, error)
	RawKeyCreator() (RawKeyCreator, error)
	KMSCrypto() (KMSCrypto, error)
	KMSCryptoSigner() (KMSCryptoSigner, error)
	KMSCryptoMultiSigner() (KMSCryptoMultiSigner, error)
	KMSCryptoVerifier() (KMSCryptoVerifier, error)
	EncrypterDecrypter() (EncrypterDecrypter, error)
	FixedKeyCrypto(pub *jwk.JWK) (FixedKeyCrypto, error)
	FixedKeySigner(kid string) (FixedKeySigner, error)
	FixedKeyMultiSigner(kid string) (FixedKeyMultiSigner, error)
}

// ErrNotSupported is returned by a Suite method when said Suite does not
// support the requested behaviour.
var ErrNotSupported = errors.New("suite does not support requested behaviour") // nolint: gochecknoglobals

// KMSCryptoVerifier provides a signature verification interface.
type KMSCryptoVerifier interface {
	Verify(sig, msg []byte, pub *jwk.JWK) error
}

// KeyCreator creates keypairs in the wrapped KMS, returning public keys in JWK format.
type KeyCreator interface {
	Create(keyType kmsapi.KeyType) (*jwk.JWK, error)
}

// KMSCrypto provides wrapped kms and crypto operations.
type KMSCrypto interface {
	KeyCreator

	Sign(msg []byte, pub *jwk.JWK) ([]byte, error)

	KMSCryptoVerifier

	FixedKeyCrypto(pub *jwk.JWK) (FixedKeyCrypto, error)
	FixedKeySigner(pub *jwk.JWK) (FixedKeySigner, error)
}

// FixedKeyCrypto provides crypto operations using a fixed key.
type FixedKeyCrypto interface {
	Sign(msg []byte) ([]byte, error)
	Verify(sig, msg []byte) error
}

// RawKeyCreator creates keypairs in the wrapped KMS, returning public keys as either JWK or the raw crypto key.
type RawKeyCreator interface {
	KeyCreator
	CreateRaw(keyType kmsapi.KeyType) (string, interface{}, error)
}

// KMSCryptoSigner provides signing operations.
type KMSCryptoSigner interface {
	Sign(msg []byte, pub *jwk.JWK) ([]byte, error)
	FixedKeySigner(pub *jwk.JWK) (FixedKeySigner, error)
}

// FixedKeySigner provides the common signer interface, using a fixed key for each signer instance.
type FixedKeySigner interface {
	Sign(msg []byte) ([]byte, error)
}

// KMSCryptoMultiSigner provides signing operations, including multi-signatures.
type KMSCryptoMultiSigner interface {
	Sign(msg []byte, pub *jwk.JWK) ([]byte, error)
	SignMulti(msgs [][]byte, pub *jwk.JWK) ([]byte, error)
	FixedKeyMultiSigner(pub *jwk.JWK) (FixedKeyMultiSigner, error)
	FixedMultiSignerGivenKID(kid string) (FixedKeyMultiSigner, error)
}

// FixedKeyMultiSigner provides a signing interface for regular and
// multi-signatures using a fixed key for each signer instance.
type FixedKeyMultiSigner interface {
	SignMulti(msgs [][]byte) ([]byte, error)
	FixedKeySigner
}

// EncrypterDecrypter provides encryption and decryption services.
type EncrypterDecrypter interface {
	Encrypt(msg, aad []byte, kid string) (cipher, nonce []byte, err error)
	Decrypt(cipher, aad, nonce []byte, kid string) (msg []byte, err error)
}
