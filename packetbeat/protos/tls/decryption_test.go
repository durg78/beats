package tls

import (
	"encoding/hex"
	"testing"
)




func TestDecryptTLS_AES_128_GCM_SHA256(t *testing.T) {
    // Application traffic secret (CLIENT_TRAFFIC_SECRET_0)
    secretHex := "65fe61867e602551686c0e85165e8267b6e53fbaa7d42b0aefd578210a996cb3"
    sequenceNumber := uint64(0)


    // Encrypted HTTP request (TLS 1.3 record payload, includes GCM tag)
    encryptedHex := "" +
		"1703030035" + 
		"199ddf52c0556b6ff2e821fd385cda76322cae44771b740c5a50db9c953f08233cfffdab5ad312f55ba0b29a335588663e37411c43"

    // Expected plaintext (HTTP GET request)
    expectedPlaintextHex := "14000020cf66d8c89837d39519dca1b32670d29e521e2f9cde1c01a12f0efdc03fb4e48f16"


    secret, err := hex.DecodeString(secretHex)
    if err != nil {
        t.Fatalf("Failed to decode secret: %v", err)
    }
    encrypted, err := hex.DecodeString(encryptedHex)
    if err != nil {
        t.Fatalf("Failed to decode encrypted: %v", err)
    }
    expected, err := hex.DecodeString(expectedPlaintextHex)
    if err != nil {
        t.Fatalf("Failed to decode expected plaintext: %v", err)
    }

	plaintext, err := DecryptTLSPacket(secret, encrypted, "TLS 1.3", "TLS_AES_128_GCM_SHA256", sequenceNumber, nil, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
    if string(plaintext) != string(expected) {
        t.Errorf("Decrypted plaintext mismatch.\nGot:  %x\nWant: %x", plaintext, expected)
    }
}

func TestDecryptTLS_AES_256_GCM_SHA384(t *testing.T) {
    // Application traffic secret (CLIENT_TRAFFIC_SECRET_0)
    secretHex := "4456493b7c9333237d1a874f0683efc2b160d67b63a4efb2601fdbd62fe88bb3035e410dfc11ceaed2579e10f387d06d"
    sequenceNumber := uint64(0)

    // Encrypted HTTP request (TLS 1.3 record payload, includes GCM tag)
    encryptedHex := "" +
		"1703030057" + 
		"a53dbe4dbdcfed5c04ea12034bd58dd43e5900ce33e4ce87bcf475f4d69e97d5d26ec42096930e97152b822eabbc36f565841d792b2bfa2692f48d534ba3699e33ef6cc3fd4c6dd27a40b218bd338736a288758cc40f9f"

    // Expected plaintext (HTTP GET request)
    expectedPlaintextHex := "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a00001804000000000000010001000000020000000000040060000000060004000000000408000000000000ef000117"



    secret, err := hex.DecodeString(secretHex)
    if err != nil {
        t.Fatalf("Failed to decode secret: %v", err)
    }
    encrypted, err := hex.DecodeString(encryptedHex)
    if err != nil {
        t.Fatalf("Failed to decode encrypted: %v", err)
    }
    expected, err := hex.DecodeString(expectedPlaintextHex)
    if err != nil {
        t.Fatalf("Failed to decode expected plaintext: %v", err)
    }

	plaintext, err := DecryptTLSPacket(secret, encrypted, "TLS 1.3", "TLS_AES_256_GCM_SHA384", sequenceNumber, nil, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
    if string(plaintext) != string(expected) {
        t.Errorf("Decrypted plaintext mismatch.\nGot:  %x\nWant: %x", plaintext, expected)
    }
}


