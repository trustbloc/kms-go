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
)

func TestNewLocalCryptoSuite(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store, err := kms.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		suite, err := NewLocalCryptoSuite("prefix://key/uri", store, &noop.NoLock{})
		require.NoError(t, err)
		require.NotNil(t, suite)
	})

	t.Run("fail to initialize localkms", func(t *testing.T) {
		store, err := kms.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		suite, err := NewLocalCryptoSuite("", store, &noop.NoLock{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "initializing local key manager")
		require.Nil(t, suite)
	})
}
