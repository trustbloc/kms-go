/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package localsuite

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/wrapper/api"
)

func newKMSCryptoMultiSigner(kms keyGetter, crypto multiSigner) api.KMSCryptoMultiSigner {
	return &multiSignerImpl{
		kms:    kms,
		crypto: crypto,
	}
}

type multiSignerImpl struct {
	kms    keyGetter
	crypto multiSigner
}

func (m *multiSignerImpl) Sign(msg []byte, pub *jwk.JWK) ([]byte, error) {
	kh, err := m.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return m.crypto.Sign(msg, kh)
}

func (m *multiSignerImpl) SignMulti(msgs [][]byte, pub *jwk.JWK) ([]byte, error) {
	kh, err := m.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return m.crypto.SignMulti(msgs, kh)
}

func (m *multiSignerImpl) FixedKeyMultiSigner(pub *jwk.JWK) (api.FixedKeyMultiSigner, error) {
	return m.FixedMultiSignerGivenKID(pub.KeyID)
}

func (m *multiSignerImpl) FixedMultiSignerGivenKID(kid string) (api.FixedKeyMultiSigner, error) {
	return getFixedMultiSigner(m.kms, m.crypto, kid)
}

func getFixedMultiSigner(kms keyGetter, crypto multiSigner, kid string) (api.FixedKeyMultiSigner, error) {
	kh, err := kms.Get(kid)
	if err != nil {
		return nil, err
	}

	return &fixedMultiSignerImpl{
		cr: crypto,
		kh: kh,
	}, nil
}

var _ api.KMSCryptoMultiSigner = &multiSignerImpl{}

type fixedMultiSignerImpl struct {
	cr multiSigner
	kh interface{}
}

func (f *fixedMultiSignerImpl) SignMulti(msgs [][]byte) ([]byte, error) {
	return f.cr.SignMulti(msgs, f.kh)
}

func (f *fixedMultiSignerImpl) Sign(msg []byte) ([]byte, error) {
	return f.cr.Sign(msg, f.kh)
}

var _ api.FixedKeyMultiSigner = &fixedMultiSignerImpl{}
