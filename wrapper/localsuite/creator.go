/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package localsuite

import (
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/wrapper/api"
)

func newKeyCreator(kms keyCreator) api.RawKeyCreator {
	return &keyCreatorImpl{kms: kms}
}

type keyCreatorImpl struct {
	kms keyCreator
}

func (k *keyCreatorImpl) Create(keyType kms.KeyType) (*jwk.JWK, error) {
	return createKey(k.kms, keyType)
}

func (k *keyCreatorImpl) ExportPubKeyBytes(id string) ([]byte, kms.KeyType, error) {
	return k.kms.ExportPubKeyBytes(id)
}

func (k *keyCreatorImpl) CreateRaw(keyType kms.KeyType) (string, interface{}, error) {
	kid, pkBytes, err := k.kms.CreateAndExportPubKeyBytes(keyType)
	if err != nil {
		return "", nil, err
	}

	raw, err := jwksupport.PubKeyBytesToKey(pkBytes, keyType)
	if err != nil {
		return "", nil, err
	}

	return kid, raw, nil
}

func createKey(creator keyCreator, keyType kms.KeyType) (*jwk.JWK, error) {
	kid, pkBytes, err := creator.CreateAndExportPubKeyBytes(keyType)
	if err != nil {
		return nil, err
	}

	pk, err := jwksupport.PubKeyBytesToJWK(pkBytes, keyType)
	if err != nil {
		return nil, err
	}

	pk.KeyID = kid

	return pk, nil
}

var _ api.KeyCreator = &keyCreatorImpl{}
