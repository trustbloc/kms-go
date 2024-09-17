/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"github.com/google/tink/go/tink"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/spi/secretlock"
)

type kmsOpts struct {
	store         kmsapi.Store
	lock          secretlock.Service
	aeadService   tink.AEAD
	primaryKeyURI string
}

// NewKMSOpt creates a new empty KMS options.
func NewKMSOpt() *kmsOpts { // nolint
	return &kmsOpts{}
}

func (k *kmsOpts) Store() kmsapi.Store {
	return k.store
}

func (k *kmsOpts) SecretLock() secretlock.Service {
	return k.lock
}

func (k *kmsOpts) AEADService() tink.AEAD {
	return k.aeadService
}

func (k *kmsOpts) PrimaryKeyURI() string {
	return k.primaryKeyURI
}

// KMSOpts are the create KMS option.
type KMSOpts func(opts *kmsOpts)

// WithStore option is for setting store for KMS.
func WithStore(store kmsapi.Store) KMSOpts {
	return func(opts *kmsOpts) {
		opts.store = store
	}
}

// WithSecretLock option is for setting secret-lock for KMS.
func WithSecretLock(secretLock secretlock.Service) KMSOpts {
	return func(opts *kmsOpts) {
		opts.lock = secretLock
	}
}

// WithPrimaryKeyURI option is for setting secret-lock for KMS.
func WithPrimaryKeyURI(primaryKeyURI string) KMSOpts {
	return func(opts *kmsOpts) {
		opts.primaryKeyURI = primaryKeyURI
	}
}

// WithAEAD option is for setting AEAD service directly for KMS.
// If not set, secretLock and primaryKeyURI will be used.
func WithAEAD(aeadService tink.AEAD) KMSOpts {
	return func(opts *kmsOpts) {
		opts.aeadService = aeadService
	}
}
