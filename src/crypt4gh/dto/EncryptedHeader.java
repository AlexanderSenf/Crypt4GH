/*
 * Copyright 2018 ELIXIR EBI
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package crypt4gh.dto;

import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;

import java.io.IOException;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

/**
 *
 * @author asenf
 */
public class EncryptedHeader implements Serializable {
    
    private byte[] checksum = null;
    private byte[] key = null;
    
    /*
     * Constructors
     */
    public EncryptedHeader(byte[] checksum, byte[] key) {
        if (checksum!=null) {
            this.checksum = new byte[64];
            System.arraycopy(checksum, 0, this.checksum, 0, 64);
        }
        this.key = new byte[32];
        System.arraycopy(key, 0, this.key, 0, 32);
    }

    private byte[] getBytes() {
        byte[] concat = new byte[96];
        System.arraycopy(this.checksum, 0, concat, 0, 64);
        System.arraycopy(this.key, 0, concat, 64, 32);
        return concat;
    }
    
    // Expects: Encrypted ByteBuffer --> Automatic Decryption
    public EncryptedHeader(byte[] encryptedBytes, byte[] sharedKey, boolean encrypted) throws InvalidKeyException, GeneralSecurityException {

        // Register Tink
        TinkConfig.register();

        // 1. Get Cipher
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(sharedKey);
        
        // 2. Enrypt
        byte[] plaintext = cipher.decrypt(encryptedBytes, new byte[0]);

        // 3. Assign
        this.checksum = new byte[64];
        System.arraycopy(plaintext, 0, this.checksum, 0, 64);
        this.key = new byte[32];
        System.arraycopy(plaintext, 64, this.key, 0, 32);
    }
    
    // Encrypt header with public key, return as byte array
    public byte[] getEncryptedHeader(byte[] sharedKey) throws GeneralSecurityException, IOException {

        // Register Tink
        TinkConfig.register();

        // 1. Get Cipher
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(sharedKey);
        
        // 2. Enrypt
        byte[] ciphertext = cipher.encrypt(this.getBytes(), new byte[0]);
        
        // 3. Return encrypted Header as Byte Array
        return ciphertext;
    }
    
    public byte[] getKey() {
        return this.key;
    }
    
    public byte[] getChecksum() {
        return this.checksum;
    }
}
