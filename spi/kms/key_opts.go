/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

// keyOpts holds options for Create, Rotate and CreateAndExportPubKeyBytes.
type keyOpts struct {
	attrs          []string
	metadata       map[string]any
	associatedData []byte
}

// NewKeyOpt creates a new empty key option.
// Not to be used directly. It's intended for implementations of KeyManager interface
// Use WithAttrs() option function below instead.
func NewKeyOpt() *keyOpts { // nolint
	return &keyOpts{
		associatedData: []byte{},
	}
}

// Attrs gets the additional attributes to be used for a key creation.
// Not to be used directly. It's intended for implementations of KeyManager interface
// Use WithAttrs() option function below instead.
func (pk *keyOpts) Attrs() []string {
	return pk.attrs
}

// Metadata gets the additional data to be stored along with the key.
func (pk *keyOpts) Metadata() map[string]any {
	return pk.metadata
}

// AssociatedData gets the associated data to be stored along with the key.
func (pk *keyOpts) AssociatedData() []byte {
	return pk.associatedData
}

// KeyOpts are the create key option.
type KeyOpts func(opts *keyOpts)

// WithAttrs option is for creating a key that requires extra attributes.
func WithAttrs(attrs []string) KeyOpts {
	return func(opts *keyOpts) {
		opts.attrs = attrs
	}
}

// WithMetadata option is for creating a key that can have additional metadata.
func WithMetadata(metadata map[string]any) KeyOpts {
	return func(opts *keyOpts) {
		opts.metadata = metadata
	}
}

// WithAssociatedData option is for creating a key that can have associated data.
func WithAssociatedData(associatedData []byte) KeyOpts {
	return func(opts *keyOpts) {
		opts.associatedData = associatedData
	}
}
