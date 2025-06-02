package tls

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
)

// This is a simplified example of how the key derivation can be done.
// In a real-world implementation, this should be adapted based on the TLS version
// and cipher suite being used.

func deriveKeys(masterKey []byte, label string, secretLen int, tlsVersion string) ([]byte, error) {
    switch tlsVersion {
    case "TLS 1.0", "TLS 1.1", "SSL":
        // TLS 1.0, TLS 1.1, and SSL use a PRF based on MD5 and SHA-1.
        return deriveKeysTLS10AndSSL(masterKey, label, secretLen)
    case "TLS 1.2":
        // TLS 1.2 uses a PRF based on HMAC-SHA256 or HMAC-SHA384.
        return deriveKeysTLS12(masterKey, label, secretLen)
    case "TLS 1.3":
        // TLS 1.3 uses HKDF for key derivation.
        return deriveKeysTLS13(masterKey, label, secretLen)
    default:
        return nil, fmt.Errorf("unsupported TLS version: %s", tlsVersion)
    }
}

// deriveKeysTLS10AndSSL handles key derivation for TLS 1.0, 1.1 and SSL.
func deriveKeysTLS10AndSSL(masterKey []byte, label string, secretLen int) ([]byte, error) {
    // Combine the label and seed as the input to the PRF.
    seed := []byte(label) // In practice, this would include additional context like random values.

    // Generate key material using MD5 and SHA-1 in parallel.
    md5PRF := hmac.New(md5.New, masterKey)
    sha1PRF := hmac.New(sha1.New, masterKey)

	md5PRF.Write(seed)
    sha1PRF.Write(seed)

    md5Output := md5PRF.Sum(nil)
    sha1Output := sha1PRF.Sum(nil)

    // Combine the outputs of MD5 and SHA-1.
    keyMaterial := make([]byte, len(md5Output))
    for i := 0; i < len(md5Output); i++ {
        keyMaterial[i] = md5Output[i] ^ sha1Output[i]
    }

    // Ensure the key material is long enough.
    if len(keyMaterial) < secretLen {
        return nil, fmt.Errorf("generated key is too short for TLS 1.0/1.1/SSL")
    }
    return keyMaterial[:secretLen], nil
}

// deriveKeysTLS12 handles key derivation for TLS 1.2.
func deriveKeysTLS12(masterKey []byte, label string, secretLen int) ([]byte, error) {
    // Combine the label and seed as the input to the PRF.
    seed := []byte(label) // In practice, this would include additional context like random values.
    prf := hmac.New(sha256.New, masterKey)

    // Generate the key material.
    prf.Write(seed)
    keyMaterial := prf.Sum(nil)

    if len(keyMaterial) < secretLen {
        return nil, fmt.Errorf("generated key is too short for TLS 1.2")
    }
    return keyMaterial[:secretLen], nil
}

// deriveKeysTLS13 handles key derivation for TLS 1.3.
func deriveKeysTLS13(masterKey []byte, label string, secretLen int) ([]byte, error) {
    // TLS 1.3 uses HKDF for key derivation.
    hkdf := hmac.New(sha256.New, masterKey)

    // The label in TLS 1.3 is more structured and includes a prefix.
    fullLabel := "tls13 " + label
    _, err := hkdf.Write([]byte(fullLabel))
    if err != nil {
        return nil, err
    }

    // Generate the key material.
    keyMaterial := hkdf.Sum(nil)

    if len(keyMaterial) < secretLen {
        return nil, fmt.Errorf("generated key is too short for TLS 1.3")
    }
    return keyMaterial[:secretLen], nil
}

func isECDHECipherSuite(cipherSuite string) bool {
    switch cipherSuite {
    case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
        return true
    default:
        return false
    }
}

func deriveECDHESharedSecret(privateKey []byte, peerPublicKey []byte) ([]byte, error) {
    // Use an elliptic curve library to compute the shared secret
    curve := elliptic.P256() // Example: P-256 curve
    priv := new(big.Int).SetBytes(privateKey)
    x, _ := elliptic.Unmarshal(curve, peerPublicKey)
    if x == nil {
        return nil, fmt.Errorf("invalid peer public key")
    }

    sharedX, _ := curve.ScalarMult(x, nil, priv.Bytes())
    return sharedX.Bytes(), nil
}


func getSecret(clientRandom string, label string, mu *sync.Mutex, keyMap *map[string]map[string]string) (string, bool) {
    mu.Lock()
    defer mu.Unlock()

    masterSecret, exists := (*keyMap)[clientRandom][label]
    return masterSecret, exists
}

// WatchSSLKeyLog watches the SSL key log file for changes, reads new lines, and loads them into a map.
func WatchSSLKeyLog(filePath string, keyMap *map[string]map[string]string, mu *sync.Mutex) {
    // Open the file for reading
    file, err := os.Open(filePath)
    if err != nil {
        log.Fatalf("Failed to open SSL key log file: %v", err)
    }
    defer file.Close()

    // Seek to the end of the file to only read new changes
    // TODO: commented out for development only
    //file.Seek(0, io.SeekEnd)

    reader := bufio.NewReader(file)

    for {
        // Read new lines from the file
        line, err := reader.ReadString('\n')
        if err != nil {
            // If no new data is available, wait and retry
            time.Sleep(1 * time.Millisecond)
            continue
        }

        // Parse the line and update the map
        parseSSLKeyLogLine(line, keyMap, mu)
    }
}

// parseSSLKeyLogLine parses a single line from the SSL key log file and updates the map.
func parseSSLKeyLogLine(line string, keyMap *map[string]map[string]string, mu *sync.Mutex) {
    // Trim whitespace and skip empty lines
    line = strings.TrimSpace(line)
    if line == "" {
        return
    }

    // Split the line into parts
    // TLS 1.2 and earlier: "CLIENT_RANDOM <Client Random> <Master Secret>"
    // TLS 1.3: "<Label> <Context> <Secret>"
    parts := strings.Fields(line)
    if len(parts) < 3 {
        log.Printf("Invalid SSL key log line: %s", line)
        return
    }

    // Handle different labels
    label := parts[0]
    clientRandom := parts[1]
    secret := parts[2]

    // Update the map with the new key-value pair
    mu.Lock()
    if _, ok := (*keyMap)[clientRandom]; !ok {
        (*keyMap)[clientRandom] = make(map[string]string)
    }
    (*keyMap)[clientRandom][label] = secret
    mu.Unlock()

   
}


const (
    // TLS 1.3 specific constants
    tls13LabelPrefix = "tls13 "
    maxHkdfLength    = 1 << 14 // 2¹⁴ bytes
)

// HKDF-Expand-Label as defined in RFC 8446, Section 7.1
func hkdfExpandLabel(secret []byte, label []byte, authAlgo string, context []byte, length int) ([]byte, error) {
    if length > maxHkdfLength {
        return nil, fmt.Errorf("length %d exceeds maximum allowed length of %d", length, maxHkdfLength)
    }

    // Construct label with prefix
    fullLabel := make([]byte, len(tls13LabelPrefix)+len(label))
    copy(fullLabel, tls13LabelPrefix)
    copy(fullLabel[len(tls13LabelPrefix):], label)

    // Total struct size: 2 (length) + 1 (label_length) + len(fullLabel) + 1 (context_length) + len(context)
    hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
    
    // Length (2 bytes)
    hkdfLabel[0] = byte(length >> 8)
    hkdfLabel[1] = byte(length)
    
    // Label length is the full length including "tls13 " prefix
    hkdfLabel[2] = byte(len(fullLabel))
    copy(hkdfLabel[3:], fullLabel)
    
    // Context length and context
    pos := 3 + len(fullLabel)
    hkdfLabel[pos] = byte(len(context))
    copy(hkdfLabel[pos+1:], context)

    if isDebug {
        debugf("HKDF input: secret=%x label=%s context=%x length=%d", secret, label, context, length)
        debugf("HKDF label bytes: %x", hkdfLabel)
    }

    // Use SHA-384 for SHA384 cipher suites
    if strings.Contains(string(authAlgo), "SHA384") {
        return hkdfExpandSHA384(secret, hkdfLabel, length), nil
    }
    return hkdfExpandSHA256(secret, hkdfLabel, length), nil
}

func hkdfExpandSHA256(prk, info []byte, length int) []byte {
    return hkdfExpand(sha256.New, prk, info, length)
}

func hkdfExpandSHA384(prk, info []byte, length int) []byte {
    return hkdfExpand(sha512.New384, prk, info, length)
}

func hkdfExpand(h func() hash.Hash, prk, info []byte, length int) []byte {
    hashLen := h().Size()
    n := (length + hashLen - 1) / hashLen
    var t []byte
    var okm []byte
    previous := []byte{}
    for i := 1; i <= n; i++ {
        mac := hmac.New(h, prk)
        mac.Write(previous)
        mac.Write(info)
        mac.Write([]byte{byte(i)})
        t = mac.Sum(nil)
        okm = append(okm, t...)
        previous = t
    }
    return okm[:length]
}

// XORs two byte slices
func xorBytes(a, b []byte) []byte {
    n := len(a)
    if len(b) < n {
        n = len(b)
    }
    out := make([]byte, n)
    for i := 0; i < n; i++ {
        out[i] = a[i] ^ b[i]
    }
    return out
}

// DecryptTLSPacketTLS13 decrypts a TLS 1.3 application data record using the provided
// application traffic secret and sequence number.
//
// Parameters:
//   - applicationTrafficSecret: The traffic secret from which key material is derived
//   - encryptedPacket: The encrypted TLS 1.3 record payload (without record header)
//   - cipherSuite: The negotiated cipher suite (e.g., "TLS_AES_128_GCM_SHA256")
//   - sequenceNumber: The record sequence number (per-direction counter starting at 0)
//
// Returns:
//   - The decrypted plaintext
//   - An error if decryption fails or parameters are invalid
//
// The function expects the encrypted packet to contain the GCM authentication tag
// as its last 16 bytes. It derives the encryption key and IV using HKDF-Expand-Label
// as specified in RFC 8446 Section 7.3.
// func DecryptTLSPacketTLS13(
//     applicationTrafficSecret []byte,
//     encryptedPacket []byte,
//     cipherSuite string,
//     sequenceNumber uint64,
// ) ([]byte, error) {
//     log.Printf("Input: secret=%x, cipher=%s, seq=%d", applicationTrafficSecret, cipherSuite, sequenceNumber)

//     // Derive key and IV using HKDF-Expand-Label
//     var keyLen, ivLen int
//     switch cipherSuite {
//     case "TLS_AES_128_GCM_SHA256":
//         keyLen = 16
//         ivLen = 12
//     case "TLS_AES_256_GCM_SHA384":
//         keyLen = 32
//         ivLen = 12
//     default:
//         return nil, fmt.Errorf("unsupported cipher suite: %s", cipherSuite)
//     }

//     var err error
//     key, err := hkdfExpandLabel(applicationTrafficSecret, []byte("key"), []byte{}, keyLen)
//     if err != nil {
//         return nil, fmt.Errorf("failed to derive key: %v", err)
//     }
//     log.Printf("Derived key: %x", key)

//     iv, err := hkdfExpandLabel(applicationTrafficSecret, []byte("iv"), []byte{}, ivLen)
//     if err != nil {
//         return nil, fmt.Errorf("failed to derive iv: %v", err)
//     }
//     log.Printf("Derived IV: %x", iv)

//     // Construct per-record nonce: XOR static IV with padded sequence number (RFC 8446, Section 5.3)
//     seqBytes := make([]byte, ivLen)
//     // Sequence number is 64-bit, encoded in network byte order (big-endian)
//     // Pad to the left with zeros to iv_length (usually 12 bytes)
//     binary.BigEndian.PutUint64(seqBytes[ivLen-8:], sequenceNumber)
//     // Now seqBytes has leading zeros followed by 8 bytes of sequence number
//     log.Printf("Sequence bytes (big-endian): %x", seqBytes)

//     nonce := xorBytes(iv, seqBytes)
//     log.Printf("Final nonce: %x", nonce)

//     // Extract ciphertext and tag (GCM tag is 16 bytes)
//     if len(encryptedPacket) < 16 {
//         return nil, fmt.Errorf("encrypted packet too short")
//     }

//     header := encryptedPacket[:5]
//     ciphertext := encryptedPacket[5:len(encryptedPacket)-16]
//     tag := encryptedPacket[len(encryptedPacket)-16:]
//     log.Printf("GCM tag: %x", tag)
//     ciphertextWithTag := make([]byte, len(ciphertext)+len(tag))
//     copy(ciphertextWithTag, ciphertext)
//     copy(ciphertextWithTag[len(ciphertext):], tag)

//     block, err := aes.NewCipher(key)
//     if err != nil {
//         return nil, err
//     }
//     aesgcm, err := cipher.NewGCM(block)
//     if err != nil {
//         return nil, err
//     }
//     // In TLS 1.3, there is no additional authenticated data (AAD) for application data records
//     plaintext, err := aesgcm.Open(nil, nonce, ciphertextWithTag, header)
    
//     if err != nil {
//         return nil, fmt.Errorf("TLS 1.3 decryption failed (sequence=%d, cipher=%s): %v", sequenceNumber, ciphertextWithTag, err)
//         // "message authentication failed" almost always means a key/IV/nonce/sequence number mismatch or tampered data.
//     }

//     return plaintext, nil
// }



// DecryptTLSPacket decrypts TLS packets for versions 1.0 through 1.3.
// It handles different cipher suites and encryption methods based on the TLS version.
//
// Parameters:
//   - secret: The secret key material (master secret for TLS ≤1.2, traffic secret for TLS 1.3)
//   - encryptedPacket: The encrypted TLS packet
//   - tlsVersion: TLS version ("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
//   - cipherSuite: The negotiated cipher suite
//   - sequenceNumber: Record sequence number (required for TLS 1.3)
//   - ecdhePrivateKey: Optional ECDHE private key for TLS ≤1.2
//   - ecdhePeerPublicKey: Optional ECDHE peer public key for TLS ≤1.2
//
// Returns:
//   - Decrypted plaintext
//   - Error if decryption fails
func DecryptTLSPacket(
    secret []byte,
    encryptedPacket []byte,
    tlsVersion string,
    cipherSuite string,
    sequenceNumber uint64,
    ecdhePrivateKey []byte,
    ecdhePeerPublicKey []byte,
) ([]byte, error) {
    if tlsVersion == "TLS 1.3" {
        return decryptTLS13(secret, encryptedPacket, cipherSuite, sequenceNumber)
    }
    return decryptLegacyTLS(secret, encryptedPacket, tlsVersion, cipherSuite, ecdhePrivateKey, ecdhePeerPublicKey)
}

func decryptTLS13(
    trafficSecret []byte,
    encryptedPacket []byte,
    cipherSuite string,
    sequenceNumber uint64,
) ([]byte, error) {
    // Extract record header (5 bytes) and payload
    if len(encryptedPacket) < 5 {
        return nil, fmt.Errorf("packet too short for TLS record header")
    }
    header := encryptedPacket[:5]
    payload := encryptedPacket[5:]

    // Derive key and IV
    var keyLen, ivLen int
    var authAlgo string
    switch cipherSuite {
    case "TLS_AES_128_GCM_SHA256":
        keyLen, ivLen = 16, 12
        authAlgo = "SHA256"
        
    case "TLS_AES_256_GCM_SHA384":
        keyLen, ivLen = 32, 12
        authAlgo = "SHA384"
    default:
        return nil, fmt.Errorf("unsupported cipher suite: %s", cipherSuite)
    }

    // Default SHA-256 derivation
    key, err := hkdfExpandLabel(trafficSecret, []byte("key"), authAlgo, []byte{}, keyLen)
    if err != nil {
        return nil, fmt.Errorf("failed to derive key: %v", err)
    }
    iv, err := hkdfExpandLabel(trafficSecret, []byte("iv"), authAlgo, []byte{}, ivLen)
    if err != nil {
        return nil, fmt.Errorf("failed to derive iv: %v", err)
    }


    // Construct nonce
    nonce := constructTLS13Nonce(iv, sequenceNumber, ivLen)

    // Split payload into ciphertext and tag
    if len(payload) < 16 {
        return nil, fmt.Errorf("payload too short for GCM tag")
    }
    ciphertext := payload[:len(payload)-16]
    tag := payload[len(payload)-16:]

    // Combine ciphertext and tag
    ciphertextWithTag := append(ciphertext, tag...)

    // Create AEAD cipher
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    aead, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    // Decrypt using header as AAD
    return aead.Open(nil, nonce, ciphertextWithTag, header)
}

func decryptLegacyTLS(
    masterKey []byte,
    encryptedPacket []byte,
    tlsVersion string,
    cipherSuite string,
    ecdhePrivateKey []byte,
    ecdhePeerPublicKey []byte,
) ([]byte, error) {
    // Extract components from packet
    if len(encryptedPacket) < 28 { // 12 (nonce) + 16 (MAC)
        return nil, fmt.Errorf("encrypted packet too short")
    }
    nonce := encryptedPacket[:12]
    ciphertext := encryptedPacket[12:len(encryptedPacket)-16]
    expectedMAC := encryptedPacket[len(encryptedPacket)-16:]

    // Handle ECDHE key exchange if needed
    var sharedSecret []byte
    var err error
    if isECDHECipherSuite(cipherSuite) {
        sharedSecret, err = deriveECDHESharedSecret(ecdhePrivateKey, ecdhePeerPublicKey)
        if err != nil {
            return nil, fmt.Errorf("ECDHE key exchange failed: %v", err)
        }
    } else {
        sharedSecret = masterKey
    }

    // Derive encryption key
    key, err := deriveKeys(sharedSecret, cipherSuite, 16, tlsVersion)
    if err != nil {
        return nil, err
    }

    // Decrypt based on cipher suite
    var plaintext []byte
    switch {
    case strings.Contains(cipherSuite, "_GCM_"):
        plaintext, err = decryptAEAD(key, nonce, ciphertext, expectedMAC)
    case strings.Contains(cipherSuite, "_CBC_"):
        plaintext, err = decryptCBC(key, nonce, ciphertext)
    default:
        return nil, fmt.Errorf("unsupported cipher suite: %s", cipherSuite)
    }

    if err != nil {
        return nil, err
    }

    // Verify MAC for non-AEAD ciphers
    if !strings.Contains(cipherSuite, "_GCM_") {
        if err := verifyMAC(plaintext, nonce, sharedSecret, cipherSuite, tlsVersion, expectedMAC); err != nil {
            return nil, err
        }
    }

    return plaintext, nil
}

func constructTLS13Nonce(iv []byte, sequenceNumber uint64, ivLen int) []byte {
    // // Construct per-record nonce: XOR static IV with padded sequence number
    // seqBytes := make([]byte, ivLen)
    // // Sequence number is 64-bit, encoded in network byte order (big-endian)
    // binary.BigEndian.PutUint64(seqBytes[ivLen-8:], sequenceNumber)
    // return xorBytes(iv, seqBytes)

        // Per RFC 8446 Section 5.3:
    // The per-record nonce is constructed as the exclusive OR of the static iv 
    // and the sequence number. The sequence number is encoded in padding-sized big-endian format.
    
    // Create nonce buffer same size as IV
    nonce := make([]byte, ivLen)
    copy(nonce, iv) // Copy IV as base
    
    // Create sequence number buffer with same length as IV
    seqBytes := make([]byte, ivLen)
    // Put sequence number at the end of the buffer (right-padded with zeros)
    binary.BigEndian.PutUint64(seqBytes[ivLen-8:], sequenceNumber)
    
    // XOR each byte of the IV with the sequence number
    for i := 0; i < ivLen; i++ {
        nonce[i] ^= seqBytes[i]
    }

    if isDebug {
        debugf("IV: %x", iv)
        debugf("Sequence bytes: %x", seqBytes)
        debugf("Final nonce: %x", nonce)
    }
    
    return nonce
}

func decryptAEAD(key, nonce, ciphertext, authTag []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create AES cipher: %v", err)
    }

    aead, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM: %v", err)
    }

    // Combine ciphertext and authentication tag
    ciphertextWithTag := append(ciphertext, authTag...)

    // Decrypt and authenticate
    plaintext, err := aead.Open(nil, nonce, ciphertextWithTag, nil)
    if err != nil {
        return nil, fmt.Errorf("AEAD decryption failed: %v", err)
    }

    return plaintext, nil
}

func decryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create AES cipher: %v", err)
    }

    if len(ciphertext)%aes.BlockSize != 0 {
        return nil, fmt.Errorf("ciphertext not a multiple of block size")
    }

    mode := cipher.NewCBCDecrypter(block, iv)
    plaintext := make([]byte, len(ciphertext))
    mode.CryptBlocks(plaintext, ciphertext)

    // Remove PKCS7 padding
    paddingLen := int(plaintext[len(plaintext)-1])
    if paddingLen > aes.BlockSize || paddingLen > len(plaintext) {
        return nil, fmt.Errorf("invalid padding length")
    }

    // Verify padding is correct
    for i := len(plaintext) - paddingLen; i < len(plaintext); i++ {
        if plaintext[i] != byte(paddingLen) {
            return nil, fmt.Errorf("invalid padding")
        }
    }

    return plaintext[:len(plaintext)-paddingLen], nil
}

func verifyMAC(plaintext, nonce, secret []byte, cipherSuite, tlsVersion string, expectedMAC []byte) error {
    // Derive MAC key
    macKey, err := deriveKeys(secret, "MAC_KEY", 32, tlsVersion)
    if err != nil {
        return fmt.Errorf("failed to derive MAC key: %v", err)
    }

    // Create HMAC based on cipher suite
    var mac hash.Hash
    switch {
    case strings.Contains(cipherSuite, "SHA384"):
        mac = hmac.New(sha512.New384, macKey)
    case strings.Contains(cipherSuite, "SHA256"):
        mac = hmac.New(sha256.New, macKey)
    case strings.Contains(cipherSuite, "SHA"):
        mac = hmac.New(sha1.New, macKey)
    default:
        return fmt.Errorf("unsupported MAC algorithm in cipher suite: %s", cipherSuite)
    }

    // Compute MAC over sequence number, header, and plaintext
    mac.Write(nonce)     // nonce includes sequence number
    mac.Write(plaintext)
    computedMAC := mac.Sum(nil)

    // Constant-time comparison of MACs
    if subtle.ConstantTimeCompare(expectedMAC, computedMAC) != 1 {
        return fmt.Errorf("MAC verification failed")
    }

    return nil
}

// Helper function to construct record length-encoded data
func makeLengthPrefixed(data []byte) []byte {
    return append([]byte{byte(len(data))}, data...)
}

// Helper function for debug logging
func logHexdump(label string, data []byte) {
    if isDebug {
        debugf("%s: %x", label, data)
    }
}