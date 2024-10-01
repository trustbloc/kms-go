/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package localsuite

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
)

// newKMSCrypto creates a KMSCrypto instance.
func newKMSCrypto(kms keyManager, crypto signerVerifier) api.KMSCrypto {
	return &kmsCryptoImpl{
		kms: kms,
		cr:  crypto,
	}
}

type kmsCryptoImpl struct {
	kms keyManager
	cr  signerVerifier
}

func (k *kmsCryptoImpl) Create(keyType kms.KeyType) (*jwk.JWK, error) {
	return createKey(k.kms, keyType)
}

func (k *kmsCryptoImpl) ExportPubKeyBytes(id string) ([]byte, kms.KeyType, error) {
	return k.kms.ExportPubKeyBytes(id)
}

func (k *kmsCryptoImpl) Sign(msg []byte, pub *jwk.JWK) ([]byte, error) {
	kh, err := k.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return k.cr.Sign(msg, kh)
}

func getKeyHandle(pub *jwk.JWK, keyManager keyHandleFetcher) (interface{}, error) {
	var (
		pkb []byte
		kt  kms.KeyType
		err error
	)

	pkb, kt, err = keyManager.ExportPubKeyBytes(pub.KeyID)
	if err != nil {
		pkb, err = pub.PublicKeyBytes()
		if err != nil {
			return nil, err
		}

		kt, err = pub.KeyType()
		if err != nil {
			return nil, err
		}
	}

	kh, err := keyManager.PubKeyBytesToHandle(pkb, kt)
	if err != nil {
		return nil, err
	}

	return kh, nil
}

func (k *kmsCryptoImpl) Verify(sig, msg []byte, pub *jwk.JWK) error {
	kh, err := getKeyHandle(pub, k.kms)
	if err != nil {
		return err
	}

	return k.cr.Verify(sig, msg, kh)
}

func (k *kmsCryptoImpl) FixedKeyCrypto(pub *jwk.JWK) (api.FixedKeyCrypto, error) {
	return makeFixedKeyCrypto(k.kms, k.cr, pub)
}

func makeFixedKeyCrypto(kms keyManager, crypto signerVerifier, pub *jwk.JWK) (api.FixedKeyCrypto, error) {
	sigKH, err := kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	verKH, err := getKeyHandle(pub, kms)
	if err != nil {
		return nil, err
	}

	return &fixedKeyImpl{
		cr:    crypto,
		sigKH: sigKH,
		verKH: verKH,
	}, nil
}

func (k *kmsCryptoImpl) FixedKeySigner(pub *jwk.JWK) (api.FixedKeySigner, error) {
	return makeFixedKeySigner(k.kms, k.cr, pub.KeyID)
}

func makeFixedKeySigner(kms keyGetter, crypto signer, kid string) (api.FixedKeySigner, error) {
	kh, err := kms.Get(kid)
	if err != nil {
		return nil, err
	}

	return &fixedKeySignerImpl{
		cr: crypto,
		kh: kh,
	}, nil
}

type fixedKeyImpl struct {
	cr    signerVerifier
	sigKH interface{}
	verKH interface{}
}

func (f *fixedKeyImpl) Sign(msg []byte) ([]byte, error) {
	return f.cr.Sign(msg, f.sigKH)
}

func (f *fixedKeyImpl) Verify(sig, msg []byte) error {
	return f.cr.Verify(sig, msg, f.verKH)
}
