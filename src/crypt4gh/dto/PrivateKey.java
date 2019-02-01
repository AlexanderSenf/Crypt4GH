/*
 * Copyright 2019 asenf.
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

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bkdf.KeyDerivationFunction;
import at.favre.lib.crypto.bkdf.Version;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 *
 * @author asenf
 */
public class PrivateKey {
    private byte[]  MAGIC_WORD = new byte[7]; // 'c4gh-v1'
    private String  kdfname;
    private int  rounds; // || salt
    private byte[] bSalt = new byte[16];
    private String  ciphername; // chacha20_poly1305
    private byte[] bEncData;
    private String  comment;
    
    private String keyPhrase; 
    
    // generate Key from input Array
    public PrivateKey(byte[] input, String keyPhrase) throws UnsupportedEncodingException {
        System.arraycopy(input, 0, this.MAGIC_WORD, 0, 7);

        int iKd_l = getBigEndianShort(Arrays.copyOfRange(input, 7, 9));
        int pos = 9;        
        this.kdfname =  new String(Arrays.copyOfRange(input, pos, pos+iKd_l));
        pos = pos + iKd_l;

        int iR_l = getBigEndianShort(Arrays.copyOfRange(input, pos, pos+2)) - 4; // subtract rounds
        pos = pos + 2;
        this.rounds = getBigEndian(Arrays.copyOfRange(input, pos, pos+4));
        pos = pos + 4;
        System.arraycopy(input, pos, this.bSalt, 0, iR_l);
        pos = pos + iR_l;
        
        int iCp_l = getBigEndianShort(Arrays.copyOfRange(input, pos, pos+2));
        pos = pos + 2;
        this.ciphername = new String(Arrays.copyOfRange(input, pos, pos+iCp_l));
        pos = pos + iCp_l;
  
        this.bEncData = new byte[input.length - pos];
        System.arraycopy(input, pos, this.bEncData, 0, this.bEncData.length);
        
        this.keyPhrase = keyPhrase;
    }

    // Decrypt and return the private key contained
    public byte[] getKey() throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] key = null;
        
        // Support multiple ciphers
        if (this.ciphername.equalsIgnoreCase("chacha20_poly1305")) {
            // Register Tink
            TinkConfig.register();
            
            // 1. Get Cipher (using bcrypt derived key)
            ChaCha20Poly1305 cipher = new ChaCha20Poly1305(getPass());

            // 2. Decrypt
            byte[] plaintext = cipher.decrypt(this.bEncData, new byte[0]);
            key = new byte[plaintext.length];
            System.arraycopy(plaintext, 0, key, 0, plaintext.length);
        }
                
        return key;
    }
    
    // Derive key from input data (bcrypt key derivation function)
    private byte[] getPass() throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {
        KeyDerivationFunction kdf = new KeyDerivationFunction.Default(Version.DEFAULT_VERSION);        
        byte[] pass = kdf.derive(this.bSalt, 
                                 this.keyPhrase.toCharArray(), 
                                 7, 
                                 null, 
                                 32);
        
        return pass;
    }
    
    private int getBigEndianShort(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).getShort();
    }
    private int getBigEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).getInt();
    }
    
    private int getLittleEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }
}
