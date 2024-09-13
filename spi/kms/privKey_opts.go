/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

// privateKeyOpts holds options for ImportPrivateKey.
type privateKeyOpts struct {
	ksID     string
	metadata map[string]any
}

// NewOpt creates a new empty private key option.
// Not to be used directly. It's intended for implementations of KeyManager interface
// Use WithKeyID() option function below instead.
func NewOpt() *privateKeyOpts { // nolint
	return &privateKeyOpts{}
}

// KsID gets the KsID to be used for import a private key.
// Not to be used directly. It's intended for implementations of KeyManager interface
// Use WithKeyID() option function below instead.
func (pk *privateKeyOpts) KsID() string {
	return pk.ksID
}

// Metadata gets the additional data to be stored along with the key.
func (pk *privateKeyOpts) Metadata() map[string]any {
	return pk.metadata
}

// PrivateKeyOpts are the import private key option.
type PrivateKeyOpts func(opts *privateKeyOpts)

// WithKeyID option is for importing a private key with a specified KeyID.
func WithKeyID(keyID string) PrivateKeyOpts {
	return func(opts *privateKeyOpts) {
		opts.ksID = keyID
	}
}

// ImportWithMetadata option is for importing a private key that can have additional metadata.
func ImportWithMetadata(metadata map[string]any) PrivateKeyOpts {
	return func(opts *privateKeyOpts) {
		opts.metadata = metadata
	}
}

// exportKeyOpts holds options for ExportPubKey.
type exportKeyOpts struct {
	getMetadata bool
}

// NewExportOpt creates a new empty export pub key option.
func NewExportOpt() *exportKeyOpts { // nolint
	return &exportKeyOpts{}
}

// GetMetadata indicates that metadata have to be exported along with the key.
func (pk *exportKeyOpts) GetMetadata() bool {
	return pk.getMetadata
}

// ExportKeyOpts are the export public key option.
type ExportKeyOpts func(opts *exportKeyOpts)

// ExportWithMetadata option is for exporting public key with metadata.
func ExportWithMetadata(getMetadata bool) ExportKeyOpts {
	return func(opts *exportKeyOpts) {
		opts.getMetadata = getMetadata
	}
}
