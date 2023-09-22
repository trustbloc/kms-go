/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package wrapper

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	mockcrypto "github.com/trustbloc/kms-go/mock/crypto"
	mockkms "github.com/trustbloc/kms-go/mock/kms"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
)

func TestKMSCrypto_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		edPub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		kc := NewKMSCrypto(&mockkms.KeyManager{
			CrAndExportPubKeyValue: edPub,
		}, &mockcrypto.Crypto{})

		pk, err := kc.Create(kmsapi.ED25519)
		require.NoError(t, err)

		require.Equal(t, "Ed25519", pk.Crv)
		require.Equal(t, "OKP", pk.Kty)
	})

	t.Run("kms err", func(t *testing.T) {
		errExpected := errors.New("expected error")

		kc := NewKMSCrypto(&mockkms.KeyManager{
			CrAndExportPubKeyErr: errExpected,
		}, &mockcrypto.Crypto{})

		pk, err := kc.Create(kmsapi.ED25519)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, pk)
	})

	t.Run("invalid public key bytes value", func(t *testing.T) {
		kc := NewKMSCrypto(&mockkms.KeyManager{
			CrAndExportPubKeyValue: []byte("invalid"),
		}, &mockcrypto.Crypto{})

		pk, err := kc.Create(kmsapi.ECDSAP256DER)
		require.Error(t, err)
		require.Contains(t, err.Error(), "asn1:")
		require.Nil(t, pk)
	})
}

func TestKmsCrypto_Sign(t *testing.T) {
	errExpected := errors.New("expected error")

	t.Run("success", func(t *testing.T) {
		expectSig := []byte("signature")

		kc := NewKMSCrypto(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{
				SignValue: expectSig,
			})

		sig, err := kc.Sign([]byte("test message"), &jwk.JWK{JSONWebKey: jose.JSONWebKey{KeyID: "foo"}})
		require.NoError(t, err)
		require.Equal(t, expectSig, sig)
	})

	t.Run("kms error", func(t *testing.T) {
		kc := NewKMSCrypto(
			&mockkms.KeyManager{
				GetKeyErr: errExpected,
			},
			&mockcrypto.Crypto{})

		sig, err := kc.Sign([]byte("test message"), &jwk.JWK{JSONWebKey: jose.JSONWebKey{KeyID: "foo"}})
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sig)
	})

	t.Run("crypto error", func(t *testing.T) {
		kc := NewKMSCrypto(
			&mockkms.KeyManager{},
			&mockcrypto.Crypto{
				SignErr: errExpected,
			})

		sig, err := kc.Sign([]byte("test message"), &jwk.JWK{JSONWebKey: jose.JSONWebKey{KeyID: "foo"}})
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sig)
	})
}

func TestKMSCrypto_Verify(t *testing.T) {
	sig := []byte("signature")
	msg := []byte("message")

	t.Run("success - own key", func(t *testing.T) {
		pk := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{KeyID: "foo"},
		}

		kc := NewKMSCrypto(&mockkms.KeyManager{}, &mockcrypto.Crypto{})

		err := kc.Verify(sig, msg, pk)
		require.NoError(t, err)
	})

	t.Run("success - other key", func(t *testing.T) {
		edPub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signerKC := NewKMSCrypto(&mockkms.KeyManager{
			CrAndExportPubKeyValue: edPub,
		}, &mockcrypto.Crypto{})

		pk, err := signerKC.Create(kmsapi.ED25519)
		require.NoError(t, err)

		kc := NewKMSCrypto(&mockkms.KeyManager{
			ExportPubKeyBytesErr: errors.New("not my key"),
		}, &mockcrypto.Crypto{})

		err = kc.Verify(sig, msg, pk)
		require.NoError(t, err)
	})

	t.Run("fail to extract public key bytes", func(t *testing.T) {
		pk := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{KeyID: "foo"},
		}

		kc := NewKMSCrypto(&mockkms.KeyManager{
			ExportPubKeyBytesErr: errors.New("not my key"),
		}, &mockcrypto.Crypto{})

		err := kc.Verify(sig, msg, pk)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported public key type")
	})

	errExpected := errors.New("expected error")

	t.Run("kms key handle error", func(t *testing.T) {
		pk := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{KeyID: "foo"},
		}

		kc := NewKMSCrypto(&mockkms.KeyManager{
			PubKeyBytesToHandleErr: errExpected,
		}, &mockcrypto.Crypto{})

		err := kc.Verify(sig, msg, pk)
		require.ErrorIs(t, err, errExpected)
	})

	t.Run("verify error", func(t *testing.T) {
		pk := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{KeyID: "foo"},
		}

		kc := NewKMSCrypto(&mockkms.KeyManager{}, &mockcrypto.Crypto{
			VerifyErr: errExpected,
		})

		err := kc.Verify(sig, msg, pk)
		require.ErrorIs(t, err, errExpected)
	})
}

func TestKmsCrypto_FixedKey(t *testing.T) {
	sig := []byte("signature")
	msg := []byte("message")
	pk := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{KeyID: "foo"},
	}
	errExpected := errors.New("expected error")

	t.Run("get fixed key crypto success", func(t *testing.T) {
		kc := NewKMSCrypto(&mockkms.KeyManager{}, &mockcrypto.Crypto{})

		fkc, err := kc.FixedKeyCrypto(pk)
		require.NoError(t, err)
		require.NotNil(t, fkc)

		fks, err := kc.FixedKeySigner(pk)
		require.NoError(t, err)
		require.NotNil(t, fks)
	})

	t.Run("get fixed key crypto error", func(t *testing.T) {
		t.Run("kms get", func(t *testing.T) {
			kc := NewKMSCrypto(&mockkms.KeyManager{
				GetKeyErr: errExpected,
			}, &mockcrypto.Crypto{})

			fkc, err := kc.FixedKeyCrypto(pk)
			require.ErrorIs(t, err, errExpected)
			require.Nil(t, fkc)

			fks, err := kc.FixedKeySigner(pk)
			require.ErrorIs(t, err, errExpected)
			require.Nil(t, fks)
		})

		t.Run("verification key handle", func(t *testing.T) {
			kc := NewKMSCrypto(&mockkms.KeyManager{
				ExportPubKeyBytesErr: errors.New("not my key"),
			}, &mockcrypto.Crypto{})

			fkc, err := kc.FixedKeyCrypto(pk)
			require.Error(t, err)
			require.Contains(t, err.Error(), "unsupported public key type")
			require.Nil(t, fkc)
		})
	})

	t.Run("sign success", func(t *testing.T) {
		kc := NewKMSCrypto(&mockkms.KeyManager{}, &mockcrypto.Crypto{
			SignValue: sig,
		})

		fkc, err := kc.FixedKeyCrypto(pk)
		require.NoError(t, err)
		require.NotNil(t, fkc)

		sigOut, err := fkc.Sign(msg)
		require.NoError(t, err)
		require.Equal(t, sig, sigOut)

		fks, err := kc.FixedKeySigner(pk)
		require.NoError(t, err)
		require.NotNil(t, fks)

		sigOut, err = fks.Sign(msg)
		require.NoError(t, err)
		require.Equal(t, sig, sigOut)
	})

	t.Run("sign error", func(t *testing.T) {
		kc := NewKMSCrypto(&mockkms.KeyManager{}, &mockcrypto.Crypto{
			SignErr: errExpected,
		})

		fkc, err := kc.FixedKeyCrypto(pk)
		require.NoError(t, err)
		require.NotNil(t, fkc)

		sigOut, err := fkc.Sign(msg)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sigOut)

		fks, err := kc.FixedKeySigner(pk)
		require.NoError(t, err)
		require.NotNil(t, fks)

		sigOut, err = fks.Sign(msg)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sigOut)
	})

	t.Run("verify success", func(t *testing.T) {
		kc := NewKMSCrypto(&mockkms.KeyManager{}, &mockcrypto.Crypto{})

		fkc, err := kc.FixedKeyCrypto(pk)
		require.NoError(t, err)
		require.NotNil(t, fkc)

		err = fkc.Verify(sig, msg)
		require.NoError(t, err)
	})

	t.Run("verify error", func(t *testing.T) {
		kc := NewKMSCrypto(&mockkms.KeyManager{}, &mockcrypto.Crypto{
			VerifyErr: errExpected,
		})

		fkc, err := kc.FixedKeyCrypto(pk)
		require.NoError(t, err)
		require.NotNil(t, fkc)

		err = fkc.Verify(sig, msg)
		require.ErrorIs(t, err, errExpected)
	})
}

func TestKMSCryptoSigner_Sign(t *testing.T) {
	sig := []byte("signature")
	msg := []byte("message")
	errExpected := errors.New("expected error")
	pk := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{KeyID: "foo"},
	}

	t.Run("success", func(t *testing.T) {
		kcs := NewKMSCryptoSigner(&mockkms.KeyManager{}, &mockcrypto.Crypto{
			SignValue: sig,
		})

		sigOut, err := kcs.Sign(msg, pk)
		require.NoError(t, err)
		require.Equal(t, sig, sigOut)
	})

	t.Run("kms get error", func(t *testing.T) {
		kcs := NewKMSCryptoSigner(&mockkms.KeyManager{
			GetKeyErr: errExpected,
		}, &mockcrypto.Crypto{})

		sigOut, err := kcs.Sign(msg, pk)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sigOut)
	})

	t.Run("crypto sign error", func(t *testing.T) {
		kcs := NewKMSCryptoSigner(&mockkms.KeyManager{}, &mockcrypto.Crypto{
			SignErr: errExpected,
		})

		sigOut, err := kcs.Sign(msg, pk)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sigOut)
	})
}

func TestKmsCryptoSigner_FixedKeySigner(t *testing.T) {
	sig := []byte("signature")
	msg := []byte("message")
	pk := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{KeyID: "foo"},
	}
	errExpected := errors.New("expected error")

	t.Run("get fixed key signer success", func(t *testing.T) {
		ks := NewKMSCryptoSigner(&mockkms.KeyManager{}, &mockcrypto.Crypto{})

		fks, err := ks.FixedKeySigner(pk)
		require.NoError(t, err)
		require.NotNil(t, fks)
	})

	t.Run("get fixed key signer error", func(t *testing.T) {
		ks := NewKMSCryptoSigner(&mockkms.KeyManager{
			GetKeyErr: errExpected,
		}, &mockcrypto.Crypto{})

		fks, err := ks.FixedKeySigner(pk)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, fks)
	})

	t.Run("sign success", func(t *testing.T) {
		kc := NewKMSCryptoSigner(&mockkms.KeyManager{}, &mockcrypto.Crypto{
			SignValue: sig,
		})

		fks, err := kc.FixedKeySigner(pk)
		require.NoError(t, err)
		require.NotNil(t, fks)

		sigOut, err := fks.Sign(msg)
		require.NoError(t, err)
		require.Equal(t, sig, sigOut)
	})

	t.Run("sign error", func(t *testing.T) {
		kc := NewKMSCryptoSigner(&mockkms.KeyManager{}, &mockcrypto.Crypto{
			SignErr: errExpected,
		})

		fks, err := kc.FixedKeySigner(pk)
		require.NoError(t, err)
		require.NotNil(t, fks)

		sigOut, err := fks.Sign(msg)
		require.ErrorIs(t, err, errExpected)
		require.Nil(t, sigOut)
	})
}
