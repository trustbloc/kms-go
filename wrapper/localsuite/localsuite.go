/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package localsuite provides an api.Suite using local kms and crypto implementations.
package localsuite

import (
	"fmt"

	"github.com/trustbloc/kms-go/crypto/tinkcrypto"
	"github.com/trustbloc/kms-go/kms/localkms"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/spi/secretlock"
	"github.com/trustbloc/kms-go/wrapper/api"
)

// NewLocalCryptoSuite initializes a wrapper.Suite using local kms and crypto
// implementations, supporting all Suite APIs.
func NewLocalCryptoSuite(
	primaryKeyURI string,
	keyStore kmsapi.Store,
	secretLock secretlock.Service,
) (api.Suite, error) {
	kms, err := localkms.New(primaryKeyURI, &kmsProv{
		store: keyStore,
		lock:  secretLock,
	})
	if err != nil {
		return nil, fmt.Errorf("initializing local key manager: %w", err)
	}

	crypto, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	return &suiteImpl{
		kms:    kms,
		crypto: crypto,
	}, nil
}

type kmsProv struct {
	store kmsapi.Store
	lock  secretlock.Service
}

func (k *kmsProv) StorageProvider() kmsapi.Store {
	return k.store
}

func (k *kmsProv) SecretLock() secretlock.Service {
	return k.lock
}
