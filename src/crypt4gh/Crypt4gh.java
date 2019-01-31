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
import static com.google.crypto.tink.subtle.X25519.computeSharedSecret;
import static com.google.crypto.tink.subtle.X25519.generatePrivateKey;
import static com.google.crypto.tink.subtle.X25519.publicFromPrivate;

import crypt4gh.dto.EncryptedHeader;
import crypt4gh.dto.PrivateKey;
import crypt4gh.dto.UnencryptedHeader;
import crypt4gh.util.Glue;

import java.io.BufferedReader;
import java.io.File;
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

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
    
    public static byte[] HeaderMethod = new byte[] {0, 0, 0, 0};
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        Options options = new Options();
        HelpFormatter formatter = new HelpFormatter();

        // Command Line Options
        options.addOption("e", "encrypt", false, "encrypt source");
        options.addOption("d", "decrypt", false, "decrypt source");
        options.addOption("f", "file", true, "file source path");
        options.addOption("o", "output", true, "output file path");
        options.addOption("k", "key", true, "data key");
        options.addOption("rk", "privatekey", true, "private key file path");
        options.addOption("rkp", "privatekeypass", true, "private key file passphrase");
        options.addOption("uk", "publickey", true, "public key file path");
        options.addOption("ukp", "publickeypass", true, "public key file passphrase");

        options.addOption("t", "testme", false, "test the operations of the algorithm");
        
        // Parse Command Line
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse( options, args);

            if (cmd.hasOption("t")) {
                testMe();
                System.exit(1);                
            }
            
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
            byte[] privateKey = loadEncryptedKey(privateKeyPath, privateKeyPassphrase);
            byte[] publicKey = loadKey(publicKeyPath);
            
            // Detect Mode (Encrypt or Decrypt) and act on it ******************
            if (cmd.hasOption("e")) { // encrypt
                //String key = cmd.getOptionValue("e");
                byte[] key = Glue.getInstance().GenerateRandomString(24, 48, 7, 7, 7, 3);
                int encryptionType = 0;        

                encrypt(inputPath, outputFilePath, encryptionType, key, privateKey, publicKey);
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
                                int encryptionType,
                                byte[] dataKey,
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
        //EncryptedHeader encryptedHeader = new EncryptedHeader(new byte[0], dataKey.getBytes());
        EncryptedHeader encryptedHeader = new EncryptedHeader(encryptionType,
                                                              dataKey);
        byte[] encryptedHeaderBytes = encryptedHeader.getEncryptedHeader(sharedKey);
        
        // Generate Unencrypted Header
        UnencryptedHeader unencryptedHeader = new UnencryptedHeader(MagicNumber, 
                                                                    Version,
                                                                    encryptedHeaderBytes.length,
                                                                    0,
                                                                    sharedKey);
        
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
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(dataKey);
        
        // Encrypt - in 64KiB segments
        byte[] segment = new byte[65535];

        /*
         * Main Encryption Loop: Process data in 64K blocks, handle Checksum
         */
        int seg_len = in.read(segment);
        while (seg_len > 0) {
            // Prepare data to be encrypted
            byte[] to_enc = Arrays.copyOf(segment, seg_len);

            // Get next data segment
            seg_len = in.read(segment);
            
            // Encrypt
            byte[] encrypted = cipher.encrypt(to_enc, new byte[0]);
            
            // Write data to output stream
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
        int encryptedHeaderLength = unencryptedHeader.getEncryptedHeaderLength();

        // Generate Curve25519 Shared Secret Key
        byte[] sharedKey = getSharedKey(privateKey, publicKey);
        
        // Get and Decrypt Header
        byte[] encryptedBytes = new byte[encryptedHeaderLength];
        int read = in.read(encryptedBytes);
        
        // Read unencrypted file Header (decryptes this header with Private GPG Key)
        EncryptedHeader encryptedHeader = new EncryptedHeader(encryptedBytes, sharedKey, true);
        
        //  Create Output Stream
        OutputStream out = Files.newOutputStream(destination);
 
        // Crypt
        TinkConfig.register();
        byte[] dataKey = encryptedHeader.getKey();
        ChaCha20Poly1305 cipher = new ChaCha20Poly1305(dataKey);
        
        // Decrypt Loop
        // Encrypt - in 64KiB segments
        byte[] segment = new byte[65563]; // 64KiB + nonce (12) + mac (16)
        
        int seg_len = in.read(segment);
        while (seg_len > 0) {
            byte[] sub_seg = Arrays.copyOfRange(segment, 0, seg_len);
            
            // Get next segment
            seg_len = in.read(segment);

            // Decrypt data
            byte[] decrypted = cipher.decrypt(sub_seg, new byte[0]); // should be 64KiB
            
            // Write decryted data to output stream
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
        byte[] header = new byte[24];
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
    private static byte[] loadEncryptedKey(Path keyIn, String keyPassIn) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, GeneralSecurityException {
        BufferedReader in = new BufferedReader(new FileReader(keyIn.toString()));
        in.readLine();
        String key = in.readLine();
        in.readLine();
        in.close();
                
        Base64 decoder = new Base64();
        byte[] decode = decoder.decode(key); //.substring(20));
        PrivateKey pk = new PrivateKey(decode, keyPassIn);
        
//        String decodeString = new String(decode);
//        PrivateKey pk = new PrivateKey(decodeString, keyPassIn);
        
//        ByteArrayInputStream bain = new ByteArrayInputStream(decode);
//        ASN1InputStream ais = new ASN1InputStream(bain);
//        while (ais.available() > 0) {
//            ASN1Primitive obj = ais.readObject();
//            
//            System.out.println(ASN1Dump.dumpAsString(obj, true));
//        }

        return pk.getKey();
    }

    /*
     * just a test run: encrypting and decrypting a file with randomly generated key pairs
     */
    private static void testMe() throws GeneralSecurityException, IOException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, Exception {
        // Party 1 (Encrypter), Party 2 (Recipient)
        byte[] privateKey_party1 = generatePrivateKey();
        byte[] publicFromPrivate_party1 = publicFromPrivate(privateKey_party1);
        byte[] privateKey_party2 = generatePrivateKey();
        byte[] publicFromPrivate_party2 = publicFromPrivate(privateKey_party2);

        // Random shared key..
        byte[] dataKey = computeSharedSecret(privateKey_party2, publicFromPrivate_party1);

        // Test to be Encrypted
        String testText = "This is a test string.";
        
        // Create temporary files (1) Origin, (2) encrypted, (3) decrypted.
        File tempFile1 = File.createTempFile("crypt4ghTest_source-", ".tmp");
        tempFile1.deleteOnExit();
        File tempFile2 = File.createTempFile("crypt4ghTest_encrypt-", ".tmp");
        tempFile2.deleteOnExit();
        File tempFile3 = File.createTempFile("crypt4ghTest_decrypt-", ".tmp");
        tempFile3.deleteOnExit();
        
        // Write test String to source
        FileWriter source = new FileWriter(tempFile1);
        source.write(testText);
        source.close();
        
        // Call encryption function 
        encrypt(tempFile1.toPath(), 
                tempFile2.toPath(), 
                0,
                dataKey,
                privateKey_party1,
                publicFromPrivate_party2);
        
        // This should have generted the encrypted file..
        System.out.println();
        
        // Now decrypt it :)
        decrypt(tempFile2.toPath(), 
                tempFile3.toPath(), 
                privateKey_party2,
                publicFromPrivate_party1);
        
        // The file should be decrypted...
        System.out.println();
        
        
    }
}