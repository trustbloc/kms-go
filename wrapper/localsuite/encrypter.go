/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package localsuite

import (
	"github.com/trustbloc/kms-go/wrapper/api"
)

func newEncrypterDecrypter(kms keyGetter, crypto encDecrypter) api.EncrypterDecrypter {
	return &crypterImpl{
		kms:    kms,
		crypto: crypto,
	}
}

type crypterImpl struct {
	kms    keyGetter
	crypto encDecrypter
}

func (c *crypterImpl) Encrypt(msg, aad []byte, kid string) (cipher, nonce []byte, err error) {
	kh, err := c.kms.Get(kid)
	if err != nil {
		return nil, nil, err
	}

	return c.crypto.Encrypt(msg, aad, kh)
}

func (c *crypterImpl) Decrypt(cipher, aad, nonce []byte, kid string) (msg []byte, err error) {
	kh, err := c.kms.Get(kid)
	if err != nil {
		return nil, err
	}

	return c.crypto.Decrypt(cipher, aad, nonce, kh)
}

var _ api.EncrypterDecrypter = &crypterImpl{}
