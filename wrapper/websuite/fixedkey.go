/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package websuite

import (
	webcrypto "github.com/trustbloc/kms-go/crypto/webkms"
	"github.com/trustbloc/kms-go/kms/webkms"
)

func makeFixedKey(
	keyID string,
	keyGetter *webkms.RemoteKMS,
	crypto *webcrypto.RemoteCrypto,
) (*fixedKeyCrypto, error) {
	keyURL, err := keyGetter.Get(keyID)
	if err != nil {
		return nil, err
	}

	return &fixedKeyCrypto{
		keyURL: keyURL,
		cr:     crypto,
	}, nil
}

type fixedKeyCrypto struct {
	keyURL interface{}
	cr     *webcrypto.RemoteCrypto
}

func (f *fixedKeyCrypto) Sign(msg []byte) ([]byte, error) {
	return f.cr.Sign(msg, f.keyURL)
}

func (f *fixedKeyCrypto) SignMulti(msgs [][]byte) ([]byte, error) {
	return f.cr.SignMulti(msgs, f.keyURL)
}

func (f *fixedKeyCrypto) Verify(sig, msg []byte) error {
	return f.cr.Verify(sig, msg, f.keyURL)
}
