/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwksupport

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/go-jose/go-jose/v3"
	"github.com/trustbloc/bbs-signature-go/bbs12381g2pub"

	"github.com/trustbloc/kms-go/doc/jose/jwk"
	cryptoapi "github.com/trustbloc/kms-go/spi/crypto"
	"github.com/trustbloc/kms-go/spi/kms"
)

const (
	ecKty          = "EC"
	okpKty         = "OKP"
	x25519Crv      = "X25519"
	bls12381G2Crv  = "BLS12381_G2"
	bls12381G2Size = 96
)

// JWKFromKey creates a JWK from an opaque key struct.
// It's e.g. *ecdsa.PublicKey, *ecdsa.PrivateKey, ed25519.VerificationMethod, *bbs12381g2pub.PrivateKey or
// *bbs12381g2pub.PublicKey.
func JWKFromKey(opaqueKey interface{}) (*jwk.JWK, error) {
	key := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: opaqueKey,
		},
	}

	// marshal/unmarshal to get all JWK's fields other than Key filled.
	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("create JWK: %w", err)
	}

	err = key.UnmarshalJSON(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("create JWK: %w", err)
	}

	return key, nil
}

// PubKeyBytesToKey creates an opaque key struct from the given public key bytes.
// It's e.g. *ecdsa.PublicKey, *ecdsa.PrivateKey, ed25519.VerificationMethod, *bbs12381g2pub.PrivateKey or
// *bbs12381g2pub.PublicKey.
func PubKeyBytesToKey(bytes []byte, keyType kms.KeyType) (interface{}, error) { // nolint:gocyclo,funlen
	switch keyType {
	case kms.ED25519Type:
		return ed25519.PublicKey(bytes), nil
	case kms.X25519ECDHKWType:
		return bytes, nil
	case kms.BLS12381G2Type:
		return bbs12381g2pub.UnmarshalPublicKey(bytes)
	case kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP521TypeIEEEP1363:
		crv := getECDSACurve(keyType)
		x, y := elliptic.Unmarshal(crv, bytes)

		return &ecdsa.PublicKey{
			Curve: crv,
			X:     x,
			Y:     y,
		}, nil
	case kms.ECDSASecp256k1TypeIEEEP1363:
		pubKey, err := btcec.ParsePubKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ecdsa secp 256k1 in IEEEP1363 format: %w", err)
		}

		return pubKey.ToECDSA(), nil

	case kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER, kms.ECDSAP521TypeDER:
		pubKey, err := x509.ParsePKIXPublicKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ecdsa key in DER format: %w", err)
		}

		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid EC key")
		}

		return ecKey, nil
	case kms.RSARS256, kms.RSAPS256:
		pubKeyRsa, err := x509.ParsePKIXPublicKey(bytes)
		if err != nil {
			return nil, errors.New("rsa: invalid public key")
		}

		return pubKeyRsa, nil
	case kms.ECDSASecp256k1TypeDER:
		return parseSecp256k1DER(bytes)
	case kms.NISTP256ECDHKWType, kms.NISTP384ECDHKWType, kms.NISTP521ECDHKWType:
		crv := getECDSACurve(keyType)
		pubKey := &cryptoapi.PublicKey{}

		err := json.Unmarshal(bytes, pubKey)
		if err != nil {
			return nil, err
		}

		ecdsaKey := &ecdsa.PublicKey{
			Curve: crv,
			X:     new(big.Int).SetBytes(pubKey.X),
			Y:     new(big.Int).SetBytes(pubKey.Y),
		}

		return ecdsaKey, nil
	default:
		return nil, fmt.Errorf("invalid key type: %s", keyType)
	}
}

// JWKFromX25519Key is similar to JWKFromKey but is specific to X25519 keys when using a public key as raw []byte.
// This builder function presets the curve and key type in the JWK.
// Using JWKFromKey for X25519 raw keys will not have these fields set and will not provide the right JWK output.
func JWKFromX25519Key(pubKey []byte) (*jwk.JWK, error) {
	key := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: pubKey,
		},
		Crv: x25519Crv,
		Kty: okpKty,
	}

	// marshal/unmarshal to get all JWK's fields other than Key filled.
	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("create JWK: %w", err)
	}

	err = key.UnmarshalJSON(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("create JWK: %w", err)
	}

	return key, nil
}

// PubKeyBytesToJWK converts marshalled bytes of keyType into JWK.
func PubKeyBytesToJWK(bytes []byte, keyType kms.KeyType) (*jwk.JWK, error) {
	switch keyType {
	case kms.ED25519Type:
		return &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key: ed25519.PublicKey(bytes),
			},
			Kty: "OKP",
			Crv: "Ed25519",
		}, nil
	case kms.X25519ECDHKWType:
		return JWKFromX25519Key(bytes)
	case kms.BLS12381G2Type,
		kms.ECDSASecp256k1TypeIEEEP1363, kms.ECDSASecp256k1TypeDER,
		kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP521TypeIEEEP1363,
		kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER, kms.ECDSAP521TypeDER,
		kms.NISTP256ECDHKWType, kms.NISTP384ECDHKWType, kms.NISTP521ECDHKWType,
		kms.RSARS256, kms.RSAPS256:
		key, err := PubKeyBytesToKey(bytes, keyType)
		if err != nil {
			return nil, err
		}

		return JWKFromKey(key)
	default:
		return nil, fmt.Errorf("convertPubKeyJWK: invalid key type: %s", keyType)
	}
}

func getECDSACurve(keyType kms.KeyType) elliptic.Curve {
	switch keyType {
	case kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP256TypeDER, kms.NISTP256ECDHKWType:
		return elliptic.P256()
	case kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP384TypeDER, kms.NISTP384ECDHKWType:
		return elliptic.P384()
	case kms.ECDSAP521TypeIEEEP1363, kms.ECDSAP521TypeDER, kms.NISTP521ECDHKWType:
		return elliptic.P521()
	case kms.ECDSASecp256k1TypeIEEEP1363, kms.ECDSASecp256k1TypeDER:
		return btcec.S256()
	}

	return nil
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func parseSecp256k1DER(keyBytes []byte) (*ecdsa.PublicKey, error) {
	var (
		pki    publicKeyInfo
		rest   []byte
		err    error
		pubKey *btcec.PublicKey
	)

	if rest, err = asn1.Unmarshal(keyBytes, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}

	pubKey, err = btcec.ParsePubKey(pki.PublicKey.RightAlign())
	if err != nil {
		return nil, err
	}

	return pubKey.ToECDSA(), nil
}

// PublicKeyFromJWK builds a cryptoapi.PublicKey from jwkKey.
func PublicKeyFromJWK(jwkKey *jwk.JWK) (*cryptoapi.PublicKey, error) {
	if jwkKey != nil {
		pubKey := &cryptoapi.PublicKey{
			KID:   jwkKey.KeyID,
			Curve: jwkKey.Crv,
			Type:  jwkKey.Kty,
		}

		switch key := jwkKey.Key.(type) {
		case *ecdsa.PublicKey:
			pubKey.X = key.X.Bytes()
			pubKey.Y = key.Y.Bytes()
		case *ecdsa.PrivateKey:
			pubKey.X = key.X.Bytes()
			pubKey.Y = key.Y.Bytes()
		case *bbs12381g2pub.PublicKey:
			bbsKey, _ := key.Marshal() //nolint:errcheck // bbs marshal public key does not return any error

			pubKey.X = bbsKey
		case *bbs12381g2pub.PrivateKey:
			bbsKey, _ := key.PublicKey().Marshal() //nolint:errcheck // bbs marshal public key does not return any error

			pubKey.X = bbsKey
		case ed25519.PublicKey:
			pubKey.X = key
		case *rsa.PublicKey:
			pubKey.N = key.N.Bytes()
			pubKey.E = big.NewInt(int64(key.E)).Bytes()
		case ed25519.PrivateKey:
			var ok bool

			pubEdKey, ok := key.Public().(ed25519.PublicKey)
			if !ok {
				return nil, errors.New("publicKeyFromJWK: invalid 25519 private key")
			}

			pubKey.X = pubEdKey
		default:
			return nil, fmt.Errorf("publicKeyFromJWK: unsupported jwk key type %T", jwkKey.Key)
		}

		return pubKey, nil
	}

	return nil, errors.New("publicKeyFromJWK: jwk is empty")
}
