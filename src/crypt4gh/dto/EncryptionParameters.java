/*
 * Copyright 2017 ELIXIR EBI
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

import static crypt4gh.dto.EncryptionParameters.Method.AES_256_CTR;
import crypt4gh.util.EncryptionMethod;
import java.nio.ByteBuffer;

/**
 *
 * @author asenf
 */
public class EncryptionParameters {

    private byte[] plaintextStart;
    private byte[] plaintextEnd;
    private byte[] ciphertextStart;
    private byte[] ciphertextEnd;
    private Method method;
    private EncryptionMethod encryptionParameters;
    
    public enum Method {
        AES_256_CTR;
    }
    
    public EncryptionParameters(long plaintextStart, long plaintextEnd,
            long ciphertextStart, long ciphertextEnd, Method method,
            EncryptionMethod encryptionParameters) {
        this.plaintextStart = longToByteArray(plaintextStart);
        this.plaintextEnd = longToByteArray(plaintextEnd);
        this.ciphertextStart = longToByteArray(ciphertextStart);
        this.ciphertextEnd = longToByteArray(ciphertextEnd);
        this.method = method;
        switch(method) {
            case AES_256_CTR:
                this.encryptionParameters = new Encryption_AES_256_CTR(encryptionParameters.getKey(),
                                                                       encryptionParameters.getIv());
                break;
        };
    }
    
    public EncryptionParameters(byte[] parameterArray) {
        this.plaintextStart = new byte[8];
        System.arraycopy(parameterArray, 0, this.plaintextStart, 0, 8);
        this.plaintextEnd = new byte[8];
        System.arraycopy(parameterArray, 8, this.plaintextEnd, 0, 8);
        this.ciphertextStart = new byte[8];
        System.arraycopy(parameterArray, 16, this.ciphertextStart, 0, 8);
        this.ciphertextEnd = new byte[8];
        System.arraycopy(parameterArray, 24, this.ciphertextEnd, 0, 8);
        byte[] methBytes = new byte[4];
        System.arraycopy(parameterArray, 32, methBytes, 0, 4);
        int meth = getLittleEndianInt(methBytes);
        switch (meth) {
            case 0:
                this.method = AES_256_CTR;
                byte[] keyBytes = new byte[32];
                System.arraycopy(parameterArray, 36, keyBytes, 0, 32);
                byte[] ivBytes = new byte[16];
                System.arraycopy(parameterArray, 68, ivBytes, 0, 16);
                this.encryptionParameters = new Encryption_AES_256_CTR(keyBytes, 
                                                                       ivBytes);
                break;
        }
    }
    
    public byte[] toByteArray() {
        byte[] concatenated = new byte[84];
        
        System.arraycopy(this.plaintextStart, 0, concatenated, 0, 8);
        System.arraycopy(this.plaintextEnd, 0, concatenated, 8, 8);
        System.arraycopy(this.ciphertextStart, 0, concatenated, 16, 8);
        System.arraycopy(this.ciphertextEnd, 0, concatenated, 24, 8);
        switch(this.method) {
            case AES_256_CTR:
                System.arraycopy(intToByteArray(0), 0, concatenated, 32, 4);
                byte[] a = this.encryptionParameters.getKey();
                byte[] b = this.encryptionParameters.getIv();
                System.arraycopy(a, 0, concatenated, 36, 32);
                System.arraycopy(b, 0, concatenated, 68, 16);
                break;
        }
        
        return concatenated;
    }
    
    // -------------------------------------------------------------------------
    public long getPlaintextStart() {
        return getLittleEndianLong(this.plaintextStart);
    }
    public long getPlaintextEnd() {
        return getLittleEndianLong(this.plaintextEnd);
    }
    public long getCiphertextStart() {
        return getLittleEndianLong(this.ciphertextStart);
    }
    public long getCiphertextEnd() {
        return getLittleEndianLong(this.ciphertextEnd);
    }
    public EncryptionMethod getEncryptionParameters() {
        return this.encryptionParameters;
    }
    
    // -------------------------------------------------------------------------
    // Convert 32 Bit Integer to Byte Array
    private byte[] intToByteArray(int a)
    {
        ByteBuffer dbuf = ByteBuffer.allocate(4);
        dbuf.order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(a);
        return dbuf.order(java.nio.ByteOrder.LITTLE_ENDIAN).array();
    }

    // Convert 64 Bit Long to Byte Array
    private byte[] longToByteArray(long a)
    {
        ByteBuffer dbuf = ByteBuffer.allocate(8);
        dbuf.order(java.nio.ByteOrder.LITTLE_ENDIAN).putLong(a);
        return dbuf.order(java.nio.ByteOrder.LITTLE_ENDIAN).array();
    }

    private int getLittleEndianInt(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }
    
    private long getLittleEndianLong(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
    }
}
