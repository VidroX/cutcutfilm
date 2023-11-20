package jwx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"os"
	"path/filepath"

	"github.com/VidroX/cutcutfilm/services/identity/core/environment"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type KeyType string

const (
	Private KeyType = "private"
	Public  KeyType = "public"
)

type Keys struct {
	PublicKey  *jwk.ECDSAPublicKey
	PrivateKey *jwk.ECDSAPrivateKey
}

var CutcutfilmKeys *Keys

func InitKeySet() (private jwk.ECDSAPrivateKey, public jwk.ECDSAPublicKey) {
	if !IsKeyPresent(Private) || !IsKeyPresent(Public) {
		if IsKeyPresent(Public) {
			_ = os.Remove(GetKeyPath(Public))
		}
		if IsKeyPresent(Private) {
			_ = os.Remove(GetKeyPath(Private))
		}

		private, public := GenerateKeySet()
		err := WriteKeySet(private, public)

		if err != nil {
			log.Fatalf("Unable to write keyset: %s\n", err)
		}

		return private, public
	}

	private, public, err := ReadKeySet()

	if err != nil {
		log.Fatalf("Unable to read keyset: %s\n", err)
	}

	return private, public
}

func GenerateKeySet() (jwk.ECDSAPrivateKey, jwk.ECDSAPublicKey) {
	raw, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate new ECDSA keys: %s\n", err)
		return nil, nil
	}

	privateKey, err := jwk.FromRaw(raw)
	if err != nil {
		log.Fatalf("Failed to construct private jwk key: %s\n", err)
		return nil, nil
	}

	if _, ok := privateKey.(jwk.ECDSAPrivateKey); !ok {
		log.Fatalf("Expected jwk.ECDSAPrivateKey, got %T\n", privateKey)
		return nil, nil
	}

	publicKey, err := jwk.PublicKeyOf(privateKey)
	if err != nil {
		log.Fatalf("Failed to construct public jwk key: %s\n", err)
		return nil, nil
	}

	if _, ok := publicKey.(jwk.ECDSAPublicKey); !ok {
		log.Fatalf("Expected jwk.ECDSAPublicKey, got %T\n", publicKey)
		return nil, nil
	}

	return privateKey.(jwk.ECDSAPrivateKey), publicKey.(jwk.ECDSAPublicKey)
}

func WriteKeySet(private jwk.ECDSAPrivateKey, public jwk.ECDSAPublicKey) error {
	err := createKeysDir()

	if err != nil {
		return err
	}

	pemEncoded, err := jwk.EncodePEM(private)

	if err != nil {
		return err
	}

	pemEncodedPub, err := jwk.EncodePEM(public)

	if err != nil {
		return err
	}

	err = os.WriteFile(GetKeyPath(Private), pemEncoded, 0444)

	if err != nil {
		return err
	}

	err = os.WriteFile(GetKeyPath(Public), pemEncodedPub, 0444)

	if err != nil {
		return err
	}

	return nil
}

func ReadKeySet() (jwk.ECDSAPrivateKey, jwk.ECDSAPublicKey, error) {
	pemEncoded, err := os.ReadFile(GetKeyPath(Private))

	if err != nil {
		return nil, nil, err
	}

	privateKey, err := jwk.ParseKey(pemEncoded, jwk.WithPEM(true))

	if err != nil {
		return nil, nil, err
	}

	if _, ok := privateKey.(jwk.ECDSAPrivateKey); !ok {
		log.Fatalf("Expected jwk.ECDSAPrivateKey, got %T\n", privateKey)
		return nil, nil, nil
	}

	pemEncodedPub, err := os.ReadFile(GetKeyPath(Public))

	if err != nil {
		return nil, nil, err
	}

	publicKey, err := jwk.ParseKey(pemEncodedPub, jwk.WithPEM(true))

	if err != nil {
		return nil, nil, err
	}

	if _, ok := publicKey.(jwk.ECDSAPublicKey); !ok {
		log.Fatalf("Expected jwk.ECDSAPublicKey, got %T\n", publicKey)
		return nil, nil, nil
	}

	return privateKey.(jwk.ECDSAPrivateKey), publicKey.(jwk.ECDSAPublicKey), nil
}

func IsKeyPresent(keyType KeyType) bool {
	_, err := os.Stat(GetKeyPath(keyType))

	return err == nil
}

func createKeysDir() error {
	var err error

	keysPath, err := filepath.Abs(filepath.Join(os.Getenv(environment.KeysDataPath), "keys"))

	if err != nil {
		return err
	}

	err = os.MkdirAll(keysPath, os.ModePerm)

	return err
}

func GetKeyPath(keyType KeyType) string {
	keysPath, _ := filepath.Abs(filepath.Join(os.Getenv(environment.KeysDataPath), "keys"))

	var fileName string
	if keyType == Public {
		fileName = "public.pem"
	} else {
		fileName = "private.pem"
	}

	return filepath.Join(keysPath, fileName)
}
