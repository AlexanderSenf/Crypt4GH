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

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 *
 * @author asenf
 */
public class UnencryptedHeader implements Serializable {
    private byte[] magicNumber = new byte[8];           // 'crypt4gh'
    private byte[] version = new byte[4];               // 0
    private byte[] publicKeyLength = new byte[4];       // 0 or # of bytes
    private byte[] publicKey;                           // {public key bytes}
    private byte[] encryptedHeaderLength = new byte[4]; // total length (inc 64 byte sig)
    
    // Instantiate header fields from byte array
    public UnencryptedHeader(byte[] bytes) {
        magicNumber = Arrays.copyOfRange(bytes, 0, 8);
        version = Arrays.copyOfRange(bytes, 8, 12);
        publicKeyLength = Arrays.copyOfRange(bytes, 12, 16);
        int len = getLittleEndian(publicKeyLength);
        if (len>0) {
            publicKey = new byte[len];
            publicKey = Arrays.copyOfRange(bytes, 16, (16+len));
        } else
            publicKey = new byte[0];
        encryptedHeaderLength = Arrays.copyOfRange(bytes, (16+len), (16+len+4));
    }
    
    // Instantiate header by providing values
    public UnencryptedHeader(byte[] magicNumber, 
                             byte[] version,
                             byte[] publicKeyLength,
                             byte[] publicKey,
                             byte[] encryptedHeaderLength) {
        this.magicNumber = Arrays.copyOf(magicNumber, 8);
        this.version = Arrays.copyOf(version, 4);
        this.publicKeyLength = Arrays.copyOf(publicKeyLength, 4);
        int len = getLittleEndian(publicKeyLength);
        if (len>0 && publicKey!= null && publicKey.length==len) {
            this.publicKey = new byte[len];
            this.publicKey = Arrays.copyOf(publicKey, len);
        } else
            this.publicKey = new byte[0];
        this.encryptedHeaderLength = Arrays.copyOf(encryptedHeaderLength, 4);
    }
    
    public UnencryptedHeader(byte[] magicNumber, 
                             byte[] version, 
                             int publicKeyLength,
                             byte[] public_key,
                             int encryptedHeaderLength) {
        this.magicNumber = Arrays.copyOf(magicNumber, 8);
        this.version = Arrays.copyOf(version, 4);
        ByteBuffer dbuf1 = ByteBuffer.allocate(4);
        dbuf1.order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(publicKeyLength);
        this.publicKeyLength = dbuf1.order(java.nio.ByteOrder.LITTLE_ENDIAN).array();        
        if (publicKeyLength>0 && public_key!= null && public_key.length==publicKeyLength) {
            this.publicKey = new byte[publicKeyLength];
            this.publicKey = Arrays.copyOf(public_key, publicKeyLength);
        } else
            this.publicKey = new byte[0];
        ByteBuffer dbuf = ByteBuffer.allocate(4);
        dbuf.order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(encryptedHeaderLength);
        this.encryptedHeaderLength = dbuf.order(java.nio.ByteOrder.LITTLE_ENDIAN).array();        
    }

    public UnencryptedHeader(ByteBuffer bb) {
        this(bb.array());
    }

    public Boolean equalsMagicNumber(byte[] magicNumber) {
        return Arrays.equals(magicNumber, this.magicNumber);
    }

    // Compare version byte arrays
    public Boolean equalsVersion(byte[] version) {
        return Arrays.equals(version, this.version);
    }
    
    // Get Version as Integer
    public int getVersion() {
        return getLittleEndian(version);
    }

    // Get lenght of encrypted header as Integer
    public int getEncryptedHeaderLength() {
        return getLittleEndian(encryptedHeaderLength);
    }
    
    // Get Public Key length as integer
    public int getPublicKeyLength() {
        return getLittleEndian(publicKeyLength);
    }
    
    // Get Public Key as String
    public String getPublicKey() {
        if (publicKey!=null && publicKey.length>0)
            return new String(publicKey);
        else
            return "";
    }
    
    // Get byte array version of header
    public byte[] getHeaderBytes() {
        int len = getLittleEndian(publicKeyLength);
        int headerLen = 20 + len;
        byte[] concatenated = new byte[headerLen];
        
        System.arraycopy(this.magicNumber, 0, concatenated, 0, 8);
        System.arraycopy(this.version, 0, concatenated, 8, 4);
        System.arraycopy(this.publicKeyLength, 0, concatenated, 12, 4);
        if (len>0)
            System.arraycopy(this.publicKey, 0, concatenated, 16, len);
        System.arraycopy(this.encryptedHeaderLength, 0, concatenated, (16+len), 4);
        
        return concatenated;
    }
    
    /*
     * Private support methods
     * - Convert byte[4] to integer; big/little endian methods
     */
    private int getLittleEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }
    
    private int getBigEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).getInt();
    }

}
