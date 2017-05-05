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

import crypt4gh.util.EgaGPGOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;


import java.util.Arrays;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

/**
 *
 * @author asenf
 */
public class EncryptedHeader implements Serializable {
    
    private int numberRecords;
    private EncryptionParameters[] encryptionParameters;

    /**
     * Bouncy Castle code for Public Key encrypted Files
     */
    private static KeyFingerPrintCalculator fingerPrintCalculater = new BcKeyFingerprintCalculator();
    private static  BcPGPDigestCalculatorProvider calc = new BcPGPDigestCalculatorProvider();
    
    // Expects: Encrypted ByteBuffer --> Automatic Decryption
    public EncryptedHeader(ByteBuffer bb, Path keyPath, String keyPassphrase) {
        try {
            // Read/Decrypt ByteBuffer content & Build Header from Plain Byte Array
            try (InputStream in = getAsymmetricGPGDecryptingInputStream(new ByteArrayInputStream(bb.array()), keyPath, keyPassphrase)) {
                
                // Read/Decrypt ByteBuffer content & Build Header from Plain Byte Array
                byte[] numRec = new byte[4];
                in.read(numRec);
                this.numberRecords = getLittleEndian(numRec);
                this.encryptionParameters = new EncryptionParameters[numberRecords];
                for (int i = 0; i<numberRecords; i++) {
                    byte[] parameter = new byte[84];
                    in.read(parameter);
                    EncryptionParameters encryptionParameter = new EncryptionParameters(parameter);
                    this.encryptionParameters[i] = encryptionParameter;
                }
                
                // Done; close streams
                in.close();
            }            
        } catch (IOException ex) {
            Logger.getLogger(EncryptedHeader.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    // Expects: Decrypted Values to create new Header (Encryption on Demand)
    public EncryptedHeader(EncryptionParameters[] encryptionParameters) {
        this.numberRecords = encryptionParameters.length;
        this.encryptionParameters = Arrays.copyOf(encryptionParameters, numberRecords);        
    }

    // Encrypt header with public key, return as byte array
    public byte[] getEncryptedHeader(Path keyPath, String keyPassphrase) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();            
        
        try {
            // Obtain Public Key
            PGPPublicKey publicKey = readPublicKeyFromCol(Files.newInputStream(keyPath));
            
            // Create Byte Array to receive encrypted header            
            OutputStream out = new EgaGPGOutputStream(baos, publicKey);
            
            // Write encrypted header
            out.write(intToByteArray(numberRecords));
            for (EncryptionParameters encryptionParameter : encryptionParameters) {
                out.write(encryptionParameter.toByteArray());
            }

            // Finish up encryption; close streams.
            out.close();
            
        } catch (IOException ex) {
            Logger.getLogger(EncryptedHeader.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException ex) {
            Logger.getLogger(EncryptedHeader.class.getName()).log(Level.SEVERE, null, ex);
        }

        // Return encrypted Header as Byte Array
        return baos.toByteArray();
    }

    // Get number of encryption blocks
    public int getNumRecords() {
        return this.numberRecords;
    }
    
    // Get parameters for one specific encryption block
    public EncryptionParameters getEncryptionParameters(int index) {
        return this.encryptionParameters[index];
    }
    
    /*
     * Decrypt a Public-Key-Encrypted Header
     *
     * Uses Bouncy Castle
     */

    // Read a Public Key from asc file
    public static PGPPublicKey readPublicKeyFromCol(InputStream in) throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());
        PGPPublicKey key = null;
        Iterator rIt = pgpPub.getKeyRings();
        while (key == null && rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();
            while (key == null && kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();
                if (k.isEncryptionKey()) {
                    key = k;
                }
            }
        }
        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }
        return key;
    }    
    
    private InputStream getAsymmetricGPGDecryptingInputStream(InputStream c_in, Path keyPath_, String keyPassphrase) {
        Security.addProvider(new BouncyCastleProvider());
        InputStream in = null;

        try {
            String[] keyPath = new String[]{keyPath_.toString(), "", keyPassphrase};

            String key = keyPath[2]; // password for key file, not password itself
            if (key==null||key.length()==0) {
                BufferedReader br = new BufferedReader(new FileReader(keyPath[1]));
                key = br.readLine();
                br.close();
            }
        
            InputStream keyIn = new BufferedInputStream(new FileInputStream(keyPath[0]));

            PGPObjectFactory pgpF = new PGPObjectFactory(c_in, fingerPrintCalculater);
            PGPEncryptedDataList    enc;
 
            Object                  o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList)
            {
                enc = (PGPEncryptedDataList)o;
            }
            else
            {
                enc = (PGPEncryptedDataList)pgpF.nextObject();
            }
             
            //
            // find the secret key
            //
            Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPrivateKey               sKey = null;
            PGPPublicKeyEncryptedData   pbe = null;
            PGPSecretKeyRingCollection  pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyIn), fingerPrintCalculater);

            while (sKey == null && it.hasNext())
            {
                try {
                    pbe = it.next();
                    
                    PGPSecretKey pgpSecKey = pgpSec.getSecretKey(pbe.getKeyID());
                    if (pgpSecKey == null)
                    {
                        sKey = null;
                    } else {
                        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(key.toCharArray());
                        //sKey = pgpSecKey.extractPrivateKey(key.toCharArray(), "BC");
                        sKey = pgpSecKey.extractPrivateKey(decryptor);
                    }
                } catch (Throwable t) {
                    System.out.println("Error -- " + t.getLocalizedMessage());
                }
            }
            
            if (sKey == null)
            {
                throw new IllegalArgumentException("secret key for message not found.");
            }
            
            BcPublicKeyDataDecryptorFactory pkddf = new BcPublicKeyDataDecryptorFactory(sKey);
            //InputStream         clear = pbe.getDataStream(sKey, "BC");
            InputStream         clear = pbe.getDataStream(pkddf);
            
            
            PGPObjectFactory    plainFact = new PGPObjectFactory(clear, fingerPrintCalculater);
            
            Object              message = plainFact.nextObject();
    
            if (message instanceof PGPCompressedData)
            {
                PGPCompressedData   cData = (PGPCompressedData)message;
                PGPObjectFactory    pgpFact = new PGPObjectFactory(cData.getDataStream(), fingerPrintCalculater);
                
                message = pgpFact.nextObject();
            }
            
            if (message instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData)message;
                in = ld.getInputStream();
            }            
        } catch (IOException | PGPException ex) {
            System.out.println(" *** " + ex.toString());
        }
        
        return in;
    }
    
    // -------------------------------------------------------------------------

    // Convert 32 Bit Integer to Byte Array
    private byte[] intToByteArray(int a)
    {
        ByteBuffer dbuf = ByteBuffer.allocate(4);
        dbuf.putInt(a).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        return dbuf.array();
    }

    // Convert 64 Bit Long to Byte Array
    private byte[] longToByteArray(long a)
    {
        ByteBuffer dbuf = ByteBuffer.allocate(8);
        dbuf.putLong(a).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        return dbuf.array();
    }

    private int getLittleEndian(byte[] bytes) {
        return java.nio.ByteBuffer.wrap(bytes).getInt();
        //return java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    }
    
}
