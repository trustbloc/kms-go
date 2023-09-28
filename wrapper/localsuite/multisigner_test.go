/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package localsuite

import (
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	mockcrypto "github.com/trustbloc/kms-go/mock/crypto"
	mockkms "github.com/trustbloc/kms-go/mock/kms"
)

func TestMultiSigner(t *testing.T) {
	var (
		msgs   = [][]byte{[]byte("foo"), []byte("qux")}
		msg    = []byte("foo bar")
		pub    = &jwk.JWK{JSONWebKey: jose.JSONWebKey{KeyID: "foo"}}
		expSig = []byte("signature")
	)

	t.Run("sign success", func(t *testing.T) {
		ms := newKMSCryptoMultiSigner(&mockkms.KeyManager{}, &mockcrypto.Crypto{
			SignValue:    expSig,
			BBSSignValue: expSig,
		})

		sig, err := ms.Sign(msg, pub)
		require.NoError(t, err)
		require.Equal(t, expSig, sig)

		sig, err = ms.SignMulti(msgs, pub)
		require.NoError(t, err)
		require.Equal(t, expSig, sig)
	})

	t.Run("fixed key success", func(t *testing.T) {
		ms := newKMSCryptoMultiSigner(&mockkms.KeyManager{}, &mockcrypto.Crypto{
			SignValue:    expSig,
			BBSSignValue: expSig,
		})

		fkms, err := ms.FixedKeyMultiSigner(pub)
		require.NoError(t, err)
		require.NotNil(t, fkms)

		fkms, err = ms.FixedMultiSignerGivenKID(pub.KeyID)
		require.NoError(t, err)
		require.NotNil(t, fkms)

		sig, err := fkms.Sign(msg)
		require.NoError(t, err)
		require.Equal(t, expSig, sig)

		sig, err = fkms.SignMulti(msgs)
		require.NoError(t, err)
		require.Equal(t, expSig, sig)
	})

	errExpected := errors.New("expected error")

	t.Run("kms get error", func(t *testing.T) {
		ms := newKMSCryptoMultiSigner(&mockkms.KeyManager{
			GetKeyErr: errExpected,
		}, &mockcrypto.Crypto{})

		sig, err := ms.Sign(msg, pub)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sig)

		sig, err = ms.SignMulti(msgs, pub)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sig)

		fkms, err := ms.FixedKeyMultiSigner(pub)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, fkms)

		fkms, err = ms.FixedMultiSignerGivenKID(pub.KeyID)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, fkms)
	})

	t.Run("sign error", func(t *testing.T) {
		ms := newKMSCryptoMultiSigner(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{
				SignErr:    errExpected,
				BBSSignErr: errExpected,
			},
		)

		sig, err := ms.Sign(msg, pub)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sig)

		sig, err = ms.SignMulti(msgs, pub)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sig)
	})

	t.Run("fixed key sign error", func(t *testing.T) {
		ms := newKMSCryptoMultiSigner(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{
				SignErr:    errExpected,
				BBSSignErr: errExpected,
			},
		)

		fkms, err := ms.FixedKeyMultiSigner(pub)
		require.NoError(t, err)
		require.NotNil(t, fkms)

		fkms, err = ms.FixedMultiSignerGivenKID(pub.KeyID)
		require.NoError(t, err)
		require.NotNil(t, fkms)

		sig, err := fkms.Sign(msg)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sig)

		sig, err = fkms.SignMulti(msgs)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sig)
	})
}
