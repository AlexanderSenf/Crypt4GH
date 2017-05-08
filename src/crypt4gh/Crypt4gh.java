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
package crypt4gh;

import crypt4gh.dto.EncryptedHeader;
import crypt4gh.dto.EncryptionParameters;
import static crypt4gh.dto.EncryptionParameters.Method.AES_256_CTR;
import crypt4gh.dto.Encryption_AES_256_CTR;
import crypt4gh.dto.UnencryptedHeader;
import crypt4gh.util.Glue;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.IOUtils;

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
        options.addOption("k", "key", true, "key file path");
        options.addOption("kp", "keypass", true, "key file passphrase");

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
            
            Path keyPath = null;
            String keyPassphrase = null;
            if (cmd.hasOption("k")) {
                String filePath = cmd.getOptionValue("k");
                keyPath = Paths.get(filePath);
                if (keyPath==null) {
                    System.exit(3);
                } else {
                    if (cmd.hasOption("kp")) {
                        keyPassphrase = cmd.getOptionValue("kp");
                    }                    
                }
            }

            // Detect Mode (Encrypt or Decrypt) and act on it ******************
            if (cmd.hasOption("e")) { // encrypt
                String aesKey = cmd.getOptionValue("e");
                encrypt(inputPath, outputFilePath, aesKey, keyPath, keyPassphrase);
            } else if (cmd.hasOption("d")) { // decrypt
                decrypt(inputPath, outputFilePath, keyPath, keyPassphrase);
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
    private static void encrypt(Path source, Path destination, String aesKey, Path keyPath, String keyPassphrase) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException  {        
        // Establish Output Stream
        OutputStream os = Files.newOutputStream(destination);
        
        // Hack: Always encrypt the whole file!        
        Encryption_AES_256_CTR parms = new Encryption_AES_256_CTR();
        parms.setKey(getKey(aesKey.toCharArray()));
        parms.setIv(getRandomIv());
        long plainEnd = Files.size(source);
        long cipherEnd = plainEnd;
        
        // Generate Encrypted Header
        EncryptionParameters[] encryptionParameters = new EncryptionParameters[1];
        encryptionParameters[0] = new EncryptionParameters(0,plainEnd,0,cipherEnd, AES_256_CTR, parms);
        EncryptedHeader encryptedHeader = new EncryptedHeader(encryptionParameters);
        byte[] encryptedHeaderBytes = encryptedHeader.getEncryptedHeader(keyPath, keyPassphrase);
        
        // Generate Unencrypted Header
        UnencryptedHeader unencryptedHeader = new UnencryptedHeader(MagicNumber, Version, encryptedHeaderBytes.length);
        
        // Write Header
        os.write(unencryptedHeader.getHeaderBytes());
        os.write(encryptedHeaderBytes);
        
        // Get Input Stream
        InputStream in = Files.newInputStream(source);
        
        // Create Encrypted Data Stream and write to output stream
        for (EncryptionParameters encryptionParameter : encryptionParameters) {
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(encryptionParameter.getEncryptionParameters().getIv());

            Cipher cipher = null;
            cipher = Cipher.getInstance("AES/CTR/NoPadding"); // load a cipher AES / Segmented Integer Counter
            SecretKey secret = new SecretKeySpec(encryptionParameter.getEncryptionParameters().getKey(), 0, 32, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secret, paramSpec);
            
            CipherOutputStream cOut = new CipherOutputStream(os, cipher);
            IOUtils.copy(in,cOut);            
            cOut.close();
        }
        
        // Done! Close the stream
        in.close();
        os.close();
    }
    
    /*
     * Decrypt
     */
    private static void decrypt(Path source, Path destination, Path keyPath, String keyPassphrase) throws IOException, Exception {
        // Get Input Stream
        InputStream in = Files.newInputStream(source);
        
        // Read unencrypted file Header (validates Magic Number & Version)
        UnencryptedHeader unencryptedHeader = getUnencryptedHeader(in);
        int encryptedHeaderLength = unencryptedHeader.getEncryptedHeaderLength();
        
        // Read unencrypted file Header (decryptes this header with Private GPG Key)
        EncryptedHeader encryptedHeader = getEncryptedHeader(in, keyPath, keyPassphrase, encryptedHeaderLength);
        
        //  Create Output Stream
        OutputStream out = Files.newOutputStream(destination);
        
        // Iterate through Data Blocks
        for (int i=0; i<encryptedHeader.getNumRecords(); i++) {
            EncryptionParameters encryptionParameter =  encryptedHeader.getEncryptionParameters(i);

            AlgorithmParameterSpec paramSpec = new IvParameterSpec(encryptionParameter.getEncryptionParameters().getIv());
            Cipher cipher = null;
            cipher = Cipher.getInstance("AES/CTR/NoPadding"); // load a cipher AES / Segmented Integer Counter
            SecretKey secret = new SecretKeySpec(encryptionParameter.getEncryptionParameters().getKey(), 0, 32, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secret, paramSpec);
            
            CipherInputStream cIn = new CipherInputStream(in, cipher);
            IOUtils.copy(cIn,out);            
        }
         
        // Done: Close Streams
        in.close();
        out.close();
    }

    /*
     * Function to read the unencrypted header of an encrypted file
     */
    private static UnencryptedHeader getUnencryptedHeader(InputStream source) throws Exception {
        //SeekableByteChannel newByteChannel = Files.newByteChannel(source);
        //ByteBuffer bb = ByteBuffer.allocate(16);
        //int read = newByteChannel.read(bb);
        //if (read<16) {
        //    throw new Exception("File is too short.");
        //}
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
    
    /*
     * Function to read the encrypted header of an encrypted file
     * Offset is always 16 bytes (length of the unencrypted header)
     * The Header object deals with decryption and encryption
     */
    private static EncryptedHeader getEncryptedHeader(InputStream source, Path keyPath, String keyPassphrase, int headerLength) throws Exception {
        //SeekableByteChannel newByteChannel = Files.newByteChannel(source);
        //ByteBuffer bb = ByteBuffer.allocate(headerLength);
        //newByteChannel.position(16);
        //int read = newByteChannel.read(bb);
        byte[] header = new byte[headerLength];
        int read = source.read(header);
        
        // Pass encrypted ByteBuffer to Header Object; automatic decryption
        EncryptedHeader encryptedHeader = new EncryptedHeader(ByteBuffer.wrap(header), keyPath, keyPassphrase);
        
        return encryptedHeader;
    }
    
    private static byte[] getRandomIv() throws NoSuchAlgorithmException {
        byte[] random_iv = new byte[16];
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.nextBytes(random_iv);
        return random_iv;
    }
    
    private static byte[] getKey(char[] password) {
        SecretKey secret = Glue.getInstance().getKey(password, 256);
        return secret.getEncoded();
    }
}
