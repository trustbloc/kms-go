/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package localsuite

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	mockkms "github.com/trustbloc/kms-go/mock/kms"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
)

func TestKeyCreator(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		keyBytes, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		keyID := "foo"

		creator := newKeyCreator(&mockkms.KeyManager{
			CrAndExportPubKeyValue: keyBytes,
			CrAndExportPubKeyID:    keyID,
		})

		pubJWK, err := creator.Create(kmsapi.ED25519Type)
		require.NoError(t, err)
		require.NotNil(t, pubJWK)
		require.IsType(t, ed25519.PublicKey{}, pubJWK.Key)

		kid, pubRaw, err := creator.CreateRaw(kmsapi.ED25519Type)
		require.NoError(t, err)
		require.NotNil(t, pubRaw)
		require.Equal(t, keyID, kid)
		require.IsType(t, ed25519.PublicKey{}, pubRaw)
	})

	t.Run("kms create err", func(t *testing.T) {
		errExpected := errors.New("expected error")

		creator := newKeyCreator(&mockkms.KeyManager{
			CrAndExportPubKeyErr: errExpected,
		})

		pubJWK, err := creator.Create(kmsapi.ED25519Type)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, pubJWK)

		kid, pubRaw, err := creator.CreateRaw(kmsapi.ED25519Type)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, pubRaw)
		require.Empty(t, kid)
	})

	t.Run("kms exports invalid key value", func(t *testing.T) {
		creator := newKeyCreator(&mockkms.KeyManager{
			CrAndExportPubKeyValue: []byte("foo"),
		})

		pubJWK, err := creator.Create(kmsapi.ECDSAP256DER)
		require.Error(t, err)
		require.Nil(t, pubJWK)

		kid, pubRaw, err := creator.CreateRaw(kmsapi.ECDSAP256DER)
		require.Error(t, err)
		require.Nil(t, pubRaw)
		require.Empty(t, kid)
	})
}
