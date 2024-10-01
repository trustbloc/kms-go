/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package websuite

import (
	webcrypto "github.com/trustbloc/kms-go/crypto/webkms"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/kms-go/kms/webkms"
	"github.com/trustbloc/kms-go/spi/kms"
	wrapperapi "github.com/trustbloc/kms-go/wrapper/api"
)

type kmsCrypto struct {
	km *webkms.RemoteKMS
	cr *webcrypto.RemoteCrypto
}

func (k *kmsCrypto) Create(keyType kms.KeyType) (*jwk.JWK, error) {
	kid, pkBytes, err := k.km.CreateAndExportPubKeyBytes(keyType)
	if err != nil {
		return nil, err
	}

	pk, err := jwksupport.PubKeyBytesToJWK(pkBytes, keyType)
	if err != nil {
		return nil, err
	}

	pk.KeyID = kid

	return pk, nil
}

func (k *kmsCrypto) ExportPubKeyBytes(id string) ([]byte, kms.KeyType, error) {
	return k.km.ExportPubKeyBytes(id)
}

func (k *kmsCrypto) CreateRaw(keyType kms.KeyType) (string, interface{}, error) {
	kid, pkBytes, err := k.km.CreateAndExportPubKeyBytes(keyType)
	if err != nil {
		return "", nil, err
	}

	raw, err := jwksupport.PubKeyBytesToKey(pkBytes, keyType)
	if err != nil {
		return "", nil, err
	}

	return kid, raw, nil
}

func (k *kmsCrypto) Sign(msg []byte, pub *jwk.JWK) ([]byte, error) {
	kh, err := k.km.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return k.cr.Sign(msg, kh)
}

func (k *kmsCrypto) SignMulti(msgs [][]byte, pub *jwk.JWK) ([]byte, error) {
	kh, err := k.km.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return k.cr.SignMulti(msgs, kh)
}

func (k *kmsCrypto) Verify(sig, msg []byte, pub *jwk.JWK) error {
	kh, err := k.km.Get(pub.KeyID)
	if err != nil {
		return err
	}

	return k.cr.Verify(sig, msg, kh)
}

func (k *kmsCrypto) Encrypt(msg, aad []byte, kid string) (cipher, nonce []byte, err error) {
	kh, err := k.km.Get(kid)
	if err != nil {
		return nil, nil, err
	}

	return k.cr.Encrypt(msg, aad, kh)
}

func (k *kmsCrypto) Decrypt(cipher, aad, nonce []byte, kid string) (msg []byte, err error) {
	kh, err := k.km.Get(kid)
	if err != nil {
		return nil, err
	}

	return k.cr.Decrypt(cipher, aad, nonce, kh)
}

func (k *kmsCrypto) FixedKeyCrypto(pub *jwk.JWK) (wrapperapi.FixedKeyCrypto, error) {
	return makeFixedKey(pub.KeyID, k.km, k.cr)
}

func (k *kmsCrypto) FixedKeySigner(pub *jwk.JWK) (wrapperapi.FixedKeySigner, error) {
	return makeFixedKey(pub.KeyID, k.km, k.cr)
}

func (k *kmsCrypto) FixedKeyMultiSigner(pub *jwk.JWK) (wrapperapi.FixedKeyMultiSigner, error) {
	return makeFixedKey(pub.KeyID, k.km, k.cr)
}

func (k *kmsCrypto) FixedMultiSignerGivenKID(kid string) (wrapperapi.FixedKeyMultiSigner, error) {
	return makeFixedKey(kid, k.km, k.cr)
}
