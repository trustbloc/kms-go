/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package localsuite

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/wrapper/api"
)

// newKMSCryptoSigner creates a KMSCryptoSigner using the given kms and crypto implementations.
func newKMSCryptoSigner(kms keyGetter, crypto signer) api.KMSCryptoSigner {
	return &kmsCryptoSignerImpl{
		kms:    kms,
		crypto: crypto,
	}
}

type kmsCryptoSignerImpl struct {
	kms    keyGetter
	crypto signer
}

func (k *kmsCryptoSignerImpl) Sign(msg []byte, pub *jwk.JWK) ([]byte, error) {
	kh, err := k.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return k.crypto.Sign(msg, kh)
}

func (k *kmsCryptoSignerImpl) FixedKeySigner(pub *jwk.JWK) (api.FixedKeySigner, error) {
	kh, err := k.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return &fixedKeySignerImpl{
		cr: k.crypto,
		kh: kh,
	}, nil
}

type fixedKeySignerImpl struct {
	cr signer
	kh interface{}
}

func (f *fixedKeySignerImpl) Sign(msg []byte) ([]byte, error) {
	return f.cr.Sign(msg, f.kh)
}
