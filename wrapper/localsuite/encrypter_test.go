/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package localsuite

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	mockcrypto "github.com/trustbloc/kms-go/mock/crypto"
	mockkms "github.com/trustbloc/kms-go/mock/kms"
)

func TestEncrypterDecrypter(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cipher := []byte("nusutto ni torinokosareshi")

		msg := []byte("the thief left it behind")
		aad := []byte("the moon, at my window")
		kid := "foo"
		nonce := []byte("e49tow4nho")

		crypter := newEncrypterDecrypter(&mockkms.KeyManager{}, &mockcrypto.Crypto{
			EncryptValue:      cipher,
			EncryptNonceValue: nonce,
			DecryptValue:      msg,
		})

		encMessage, gotNonce, err := crypter.Encrypt(msg, aad, kid)
		require.NoError(t, err)
		require.Equal(t, cipher, encMessage)
		require.Equal(t, nonce, gotNonce)

		gotMsg, err := crypter.Decrypt(encMessage, aad, nonce, kid)
		require.NoError(t, err)
		require.Equal(t, gotMsg, msg)
	})

	t.Run("kms get err", func(t *testing.T) {
		errExpected := errors.New("expected error")

		crypter := newEncrypterDecrypter(&mockkms.KeyManager{
			GetKeyErr: errExpected,
		}, &mockcrypto.Crypto{})

		enc, nonce, err := crypter.Encrypt(nil, nil, "")
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, enc)
		require.Nil(t, nonce)

		msg, err := crypter.Decrypt(nil, nil, nil, "")
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, msg)
	})

	t.Run("crypto err", func(t *testing.T) {
		errExpected := errors.New("expected error")

		crypter := newEncrypterDecrypter(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{
				EncryptErr: errExpected,
				DecryptErr: errExpected,
			},
		)

		enc, nonce, err := crypter.Encrypt(nil, nil, "")
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, enc)
		require.Nil(t, nonce)

		msg, err := crypter.Decrypt(nil, nil, nil, "")
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, msg)
	})
}
