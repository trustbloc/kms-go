/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/kms-go/crypto/tinkcrypto/primitive/aead/subtle"
)

func TestValidateAESKeySize(t *testing.T) {
	for i := range uint32(65) {
		err := subtle.ValidateAESKeySize(i)

		switch i {
		case 16, 24, 32: // Valid key sizes.
			require.NoError(t, err)

		default:
			// Invalid key sizes.
			require.Errorf(t, err, "invalid key size (%d) should not be accepted", i)

			require.Contains(t, err.Error(), "invalid AES key size; want 16, 24 or 32")
		}
	}
}
