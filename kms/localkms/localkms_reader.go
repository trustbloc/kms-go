/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/trustbloc/kms-go/spi/kms"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
)

// newReader will create a new local storage storeReader of a keyset with ID value = keysetID
// it is used internally by local kms.
func newReader(store kms.Store, keysetID string, opts ...kmsapi.ExportKeyOpts) *storeReader {
	pOpts := kmsapi.NewExportOpt()

	for _, opt := range opts {
		opt(pOpts)
	}

	return &storeReader{
		storage:        store,
		keysetID:       keysetID,
		getMetadata:    pOpts.GetMetadata(),
		associatedData: pOpts.AssociatedData(),
	}
}

// storeReader struct to load a keyset from a local storage.
type storeReader struct {
	buf            *bytes.Buffer
	storage        kms.Store
	keysetID       string
	getMetadata    bool
	metadata       map[string]any
	associatedData []byte
}

// Read the keyset from local storage into p.
func (l *storeReader) Read(p []byte) (int, error) {
	if l.buf != nil {
		return l.buf.Read(p)
	}

	if l.keysetID == "" {
		return 0, errors.New("keysetID is not set")
	}

	var data []byte

	var err error

	var metadata map[string]any

	if l.getMetadata {
		metadataStorage, ok := l.storage.(kmsapi.StoreWithMetadata)
		if !ok {
			return 0, errors.New("requested to get 'metadata', but storage doesn't support it")
		}

		data, metadata, err = metadataStorage.GetWithMetadata(l.keysetID)
	} else {
		data, err = l.storage.Get(l.keysetID)
	}

	if err != nil {
		return 0, fmt.Errorf("cannot read data for keysetID %s: %w", l.keysetID, err)
	}

	l.metadata = metadata
	l.buf = bytes.NewBuffer(data)

	return l.buf.Read(p)
}
