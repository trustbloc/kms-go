/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package wrapper

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
)

// KMSCryptoVerifier provides a signature verification interface.
type KMSCryptoVerifier interface {
	Verify(sig, msg []byte, pub *jwk.JWK) error
}

// KMSCrypto provides wrapped kms and crypto operations.
type KMSCrypto interface {
	Create(keyType kmsapi.KeyType) (*jwk.JWK, error)
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

// NewKMSCrypto creates a KMSCrypto instance.
func NewKMSCrypto(kms keyManager, crypto signerVerifier) KMSCrypto {
	return &kmsCryptoImpl{
		kms: kms,
		cr:  crypto,
	}
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

// NewKMSCryptoSigner creates a KMSCryptoSigner using the given kms and crypto implementations.
func NewKMSCryptoSigner(kms keyGetter, crypto signer) KMSCryptoSigner {
	return &kmsCryptoSignerImpl{
		kms:    kms,
		crypto: crypto,
	}
}
