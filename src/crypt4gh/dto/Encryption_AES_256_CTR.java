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

import crypt4gh.util.EncryptionMethod;
import org.bouncycastle.util.Arrays;

/**
 *
 * @author asenf
 */
public class Encryption_AES_256_CTR implements EncryptionMethod {
    
    private byte[] key = null;
    private byte[] iv = null;

    public Encryption_AES_256_CTR() {
    }

    public Encryption_AES_256_CTR(byte[] key, byte[] iv) {
        this.key = Arrays.copyOf(key, 32);
        this.iv = Arrays.copyOf(iv, 16);
    }
    
    public byte[] getKey() {
        return key;
    }
    
    public byte[] getIv() {
        return iv;
    }    

    public void setKey(byte[] key) {
        this.key = Arrays.copyOf(key, 32);
    }

    public void setIv(byte[] iv) {
        this.iv = Arrays.copyOf(iv, 16);
    }
}
