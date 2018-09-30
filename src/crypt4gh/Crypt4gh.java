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
package crypt4gh;

import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.subtle.ChaCha20Poly1305;
import com.google.crypto.tink.subtle.X25519;

import crypt4gh.dto.EncryptedHeader;
import crypt4gh.dto.UnencryptedHeader;
import crypt4gh.util.Glue;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author asenf
 * 
 * Proof-of-concept implementation of Crypt4GH File Format proposal
 * 
 */
public class Crypt4gh {

    // 'crypt4gh' version 1
    public static byte[] MagicNumber = new byte[] {99, 114, 121, 112, 116, 52, 103, 104};
    public static byte[] Version = new byte[] {1, 0, 0, 0};
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        Options options = new Options();
        HelpFormatter formatter = new HelpFormatter();

        // Command Line Options
        options.addOption("e", "encrypt", true, "encrypt source");
        options.addOption("d", "decrypt", false, "decrypt source");
        options.addOption("f", "file", true, "file source path");
        options.addOption("o", "output", true, "output file path");
        options.addOption("k", "key", true, "data key");
        options.addOption("rk", "privatekey", true, "private key file path");
        options.addOption("rkp", "privatekeypass", true, "private key file passphrase");
        options.addOption("uk", "publickey", true, "public key file path");
        options.addOption("ukp", "publickeypass", true, "public key file passphrase");

        // Parse Command Line
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse( options, args);

            // Input File Path
            Path inputPath = null;
            if (cmd.hasOption("f")) {
                String filePath = cmd.getOptionValue("f");
                inputPath = Paths.get(filePath);
                if (inputPath==null) {
                    System.exit(1);
                }
            }

            // Output File Path
            Path outputFilePath = null;
            if (cmd.hasOption("o")) {
                String filePath = cmd.getOptionValue("o");
                outputFilePath = Paths.get(filePath);
                if (outputFilePath==null) {
                    System.exit(2);
                }
            }

            // Private Key
            Path privateKeyPath = null;
            String privateKeyPassphrase = null;
            if (cmd.hasOption("rk")) {
                String filePath = cmd.getOptionValue("rk");
                privateKeyPath = Paths.get(filePath);
                if (privateKeyPath==null) {
                    System.exit(3);
                } else {
                    if (cmd.hasOption("rkp")) {
                        privateKeyPassphrase = cmd.getOptionValue("rkp");
                    }                    
                }
            }

            // Public Key
            Path publicKeyPath = null;
            String publicKeyPassphrase = null;
            if (cmd.hasOption("uk")) {
                String filePath = cmd.getOptionValue("uk");
                publicKeyPath = Paths.get(filePath);
                if (publicKeyPath==null) {
                    System.exit(3);
                } else {
                    if (cmd.hasOption("ukp")) {
                        publicKeyPassphrase = cmd.getOptionValue("ukp");
                    }                    
                }
            }
            
            // Load Keys
            byte[] privateKey = null;
            byte[] publicKey = null;
            
            // Detect Mode (Encrypt or Decrypt) and act on it ******************
            if (cmd.hasOption("e")) { // encrypt
                String key = cmd.getOptionValue("e");
                encrypt(inputPath, outputFilePath, key, privateKey, publicKey);
            } else if (cmd.hasOption("d")) { // decrypt
                decrypt(inputPath, outputFilePath, privateKey, publicKey);
            } // ***************************************************************
            
        } catch (ParseException ex) {
            formatter.printHelp( "java -jar crypt4gh.jar", options, true );            
            System.out.println("Unrecognized Parameter. " + ex.getLocalizedMessage());
            Logger.getLogger(Crypt4gh.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            formatter.printHelp( "java -jar crypt4gh.jar", options, true );            
            System.out.println("File IO Exception. " + ex.getLocalizedMessage());
            Logger.getLogger(Crypt4gh.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            System.out.println("File Exception. " + ex.getLocalizedMessage());
            Logger.getLogger(Crypt4gh.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Progressed to this point without errors: Done!
    }
    
    /*
     * Encrypt
     */
    private static void encrypt(Path source, 
                                Path destination, 
                                String dataKey,
                                byte[] privateKey,
                                byte[] publicKey) throws IOException, 
                                                           NoSuchAlgorithmException, 
                                                           NoSuchPaddingException, 
                                                           InvalidKeyException, 
                                                           InvalidAlgorithmParameterException, 
                                                           GeneralSecurityException  {        
        // Establish Output Stream
        OutputStream os = Files.newOutputStream(destination);

        // Generate Curve25519 Shared Secret Key
        byte[] sharedKey = getSharedKey(privateKey, publicKey);
        
        // Generate Encrypted Header and nonce and MAC
        EncryptedHeader encryptedHeader = new EncryptedHeader(new byte[0], dataKey.getBytes());
        byte[] encryptedHeaderBytes = encryptedHeader.getEncryptedHeader(sharedKey);
        
        // Generate Unencrypted Header
        UnencryptedHeader unencryptedHeader = new UnencryptedHeader(MagicNumber, 
                                                                    Version,
                                                                    0,
                                                                    null,
                                                                    encryptedHeaderBytes.length + 20);
        
        // Write Header
        os.write(unencryptedHeader.getHeaderBytes());
        os.write(encryptedHeaderBytes);
        
        //
        // Header is written. Write actual file data
        //
        
        // Get Input Stream
        InputStream in = Files.newInputStream(source);
        
        // Crypt
        TinkConfig.register();
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(dataKey.getBytes());
        
        // Encrypt - in 64KiB segments
        byte[] segment = new byte[65535];
        
        int seg_len = in.read(segment);
        while (seg_len > 0) {
            byte[] encrypted = cipher.encrypt(segment, new byte[0]);
            
            os.write(encrypted);
        }
        in.close();
        
        os.flush();
        os.close();
    }
    
    /*
     * Decrypt
     */
    private static void decrypt(Path source, 
                                Path destination, 
                                byte[] privateKey,
                                byte[] publicKey) throws IOException, 
                                                         NoSuchAlgorithmException, 
                                                         NoSuchPaddingException, 
                                                         InvalidKeyException, 
                                                         InvalidAlgorithmParameterException, 
                                                         GeneralSecurityException,
                                                         Exception  {
        // Get Input Stream
        InputStream in = Files.newInputStream(source);
        
        // Read unencrypted file Header (validates Magic Number & Version)
        UnencryptedHeader unencryptedHeader = getUnencryptedHeader(in);
        int encryptedHeaderLength = unencryptedHeader.getEncryptedHeaderLength() - 20;

        // Generate Curve25519 Shared Secret Key
        byte[] sharedKey = getSharedKey(privateKey, publicKey);
        
        // Get and Decrypt Header
        byte[] encryptedBytes = new byte[encryptedHeaderLength];
        in.read(encryptedBytes);
        
        // Read unencrypted file Header (decryptes this header with Private GPG Key)
        EncryptedHeader encryptedHeader = new EncryptedHeader(encryptedBytes, sharedKey, true);
        
        //  Create Output Stream
        OutputStream out = Files.newOutputStream(destination);
 
        // Crypt
        TinkConfig.register();
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(encryptedHeader.getKey());
        
        // Decrypt
        // Encrypt - in 64KiB segments
        byte[] segment = new byte[65563]; // 64KiB + nonce (12) + mac (16)
        
        int seg_len = in.read(segment);
        while (seg_len > 0) {
            byte[] decrypted = cipher.encrypt(segment, new byte[0]); // should be 64KiB
            
            out.write(decrypted);
        }
         
        // Done: Close Streams
        in.close();
        out.flush();
        out.close();
    }

    /*
     * Function to read the unencrypted header of an encrypted file
     */
    private static UnencryptedHeader getUnencryptedHeader(InputStream source) throws Exception {
        byte[] header = new byte[16];
        source.read(header);

        // Generate Header Object
        UnencryptedHeader unencryptedHeader = new UnencryptedHeader(ByteBuffer.wrap(header));
        
        // Validate File Magic Number & Version
        if (!unencryptedHeader.equalsMagicNumber(MagicNumber)) {
            throw new Exception("This is not a CRYPT4GH File.");
        }
        
        // Validate Crypt4GH Version
        if (!unencryptedHeader.equalsVersion(Version)) {
            throw new Exception("Incorrect CRYPT4GH Version.");
        }
        
        return unencryptedHeader;
    }
        
    private static byte[] getKey(char[] password) {
        SecretKey secret = Glue.getInstance().getKey(password, 256);
        return secret.getEncoded();
    }
    
    // Incomplete!
    private static void generateX25519Key(Path keyOut) throws IOException {
        byte[] generatePrivateKey = X25519.generatePrivateKey();

        FileWriter out = new FileWriter(keyOut.toString());
        Base64 encoder = new Base64(64);
        
        String key_begin = "-----BEGIN PRIVATE KEY-----\n";
        String end_key = "-----END PRIVATE KEY-----";

        // Todo: ANS.1 Format
        
        String pemKeyPre = new String(encoder.encode(generatePrivateKey));
        String pemKey = key_begin + pemKeyPre + end_key;        
        try {
            out.write(pemKey);
        } finally {
            out.close();
        }
    }

    private static byte[] getSharedKey(byte[] myPrivate, byte[] userPublic) throws InvalidKeyException {
        byte[] computeSharedSecret = X25519.computeSharedSecret(myPrivate, userPublic);
        return computeSharedSecret;
    }
    
    private static byte[] loadKey(Path keyIn) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        BufferedReader in = new BufferedReader(new FileReader(keyIn.toString()));
        in.readLine();
        String key = in.readLine();
        in.readLine();
        in.close();
        
        Base64 decoder = new Base64(64);
        byte[] decode = decoder.decode(key); //.substring(20));
        
//        ByteArrayInputStream bain = new ByteArrayInputStream(decode);
//        ASN1InputStream ais = new ASN1InputStream(bain);
//        while (ais.available() > 0) {
//            ASN1Primitive obj = ais.readObject();
//            
//            System.out.println(ASN1Dump.dumpAsString(obj, true));
//        }        
        return decode;
    }
 
}
