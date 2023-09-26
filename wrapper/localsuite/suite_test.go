/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package localsuite

import (
	"testing"

	"github.com/stretchr/testify/require"
	mockstorage "github.com/trustbloc/kms-go/internal/mock/storage"
	"github.com/trustbloc/kms-go/kms"
	"github.com/trustbloc/kms-go/secretlock/noop"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
)

func TestSuite(t *testing.T) {
	store, e := kms.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
	require.NoError(t, e)

	suite, e := NewLocalCryptoSuite("local-lock://custom/primary/key/", store, &noop.NoLock{})
	require.NoError(t, e)

	creator, e := suite.KeyCreator()
	require.NoError(t, e)

	pub, e := creator.Create(kmsapi.BLS12381G2Type)
	require.NoError(t, e)

	t.Run("KMSCryptoVerifier", func(t *testing.T) {
		kcv, err := suite.KMSCryptoVerifier()
		require.NoError(t, err)
		require.NotNil(t, kcv)
	})

	t.Run("KeyCreator", func(t *testing.T) {
		c, err := suite.KeyCreator()
		require.NoError(t, err)
		require.NotNil(t, c)
	})

	t.Run("KMSCrypto", func(t *testing.T) {
		kc, err := suite.KMSCrypto()
		require.NoError(t, err)
		require.NotNil(t, kc)
	})

	t.Run("FixedKeyCrypto", func(t *testing.T) {
		fkc, err := suite.FixedKeyCrypto(pub)
		require.NoError(t, err)
		require.NotNil(t, fkc)
	})

	t.Run("RawKeyCreator", func(t *testing.T) {
		rc, err := suite.RawKeyCreator()
		require.NoError(t, err)
		require.NotNil(t, rc)
	})

	t.Run("KMSCryptoSigner", func(t *testing.T) {
		kcs, err := suite.KMSCryptoSigner()
		require.NoError(t, err)
		require.NotNil(t, kcs)
	})

	t.Run("FixedKeySigner", func(t *testing.T) {
		fks, err := suite.FixedKeySigner(pub.KeyID)
		require.NoError(t, err)
		require.NotNil(t, fks)
	})

	t.Run("KMSCryptoMultiSigner", func(t *testing.T) {
		kcms, err := suite.KMSCryptoMultiSigner()
		require.NoError(t, err)
		require.NotNil(t, kcms)
	})

	t.Run("FixedKeyMultiSigner", func(t *testing.T) {
		fkms, err := suite.FixedKeyMultiSigner(pub.KeyID)
		require.NoError(t, err)
		require.NotNil(t, fkms)
	})

	t.Run("EncrypterDecrypter", func(t *testing.T) {
		enc, err := suite.EncrypterDecrypter()
		require.NoError(t, err)
		require.NotNil(t, enc)
	})
}
