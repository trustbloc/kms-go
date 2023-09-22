/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package wrapper

import (
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
)

type signer interface {
	Sign(msg []byte, kh interface{}) ([]byte, error)
}

type verifier interface {
	Verify(signature []byte, msg []byte, kh interface{}) error
}

type signerVerifier interface {
	signer
	verifier
}

type keyGetter interface {
	Get(keyID string) (interface{}, error)
}

type keyHandleFetcher interface {
	PubKeyBytesToHandle(pubKeyBytes []byte, keyType kmsapi.KeyType, opts ...kmsapi.KeyOpts) (interface{}, error)
	ExportPubKeyBytes(keyID string) ([]byte, kmsapi.KeyType, error)
	keyGetter
}

type keyCreator interface {
	CreateAndExportPubKeyBytes(kt kmsapi.KeyType, opts ...kmsapi.KeyOpts) (string, []byte, error)
}

type keyManager interface {
	keyCreator
	keyHandleFetcher
}
