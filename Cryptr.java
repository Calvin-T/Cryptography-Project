/*
 *               Cryptr
 *
 * Cryptr is a java encryption toolset
 * that can be used to encrypt/decrypt files
 * and keys locally, allowing for files to be
 * shared securely over the world wide web
 *
 * Cryptr provides the following functions:
 *	 1. Generating a secret key
 *   2. Encrypting a file with a secret key
 *   3. Decrypting a file with a secret key
 *   4. Encrypting a secret key with a public key
 *   5. Decrypting a secret key with a private key
 *
 */

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.io.*;
import java.security.*;
import java.security.spec.*;

public class Cryptr {


	/**
	 * Generates an 128-bit AES secret key and writes it to a file
	 *
	 * @param  secKeyFile    name of file to store secret key
	 */
	static void generateKey(String secKeyFile) throws Exception{

		// Create key
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		SecretKey skey = kgen.generateKey();

		// Save key to file
		String keyFile = secKeyFile;
		try (FileOutputStream out = new FileOutputStream(keyFile)) {
		    byte[] keyb = skey.getEncoded();
		    out.write(keyb);
		}


	}

	static private void processFile(Cipher ci,String inFile,String outFile, byte[] iv, boolean encrypt)
	    throws javax.crypto.IllegalBlockSizeException,
	           javax.crypto.BadPaddingException,
	           java.io.IOException
	    {
	        try (FileInputStream in = new FileInputStream(inFile);
	             FileOutputStream out = new FileOutputStream(outFile)) {
							// Write the first 16 bytes as the iv
							if( encrypt ){
								out.write(iv);
							}

							// If decrypt then skip first 16
							if( !encrypt ){
								in.skip(128/8);
							}

							// Write to output file
	            byte[] ibuf = new byte[1024];
	            int len;
	            while ((len = in.read(ibuf)) != -1) {
	                byte[] obuf = ci.update(ibuf, 0, len);
	                if ( obuf != null ) out.write(obuf);
	            }
	            byte[] obuf = ci.doFinal();
	            if ( obuf != null ) out.write(obuf);



	        }
	    }

	/**
	 * Extracts secret key from a file, generates an
	 * initialization vector, uses them to encrypt the original
	 * file, and writes an encrypted file containing the initialization
	 * vector followed by the encrypted file data
	 *
	 * @param  originalFile    name of file to encrypt
	 * @param  secKeyFile      name of file storing secret key
	 * @param  encryptedFile   name of file to write iv and encrypted file data
	 */
	static void encryptFile(String originalFile, String secKeyFile, String encryptedFile)
		throws java.io.IOException, java.security.NoSuchAlgorithmException, java.security.InvalidKeyException, javax.crypto.IllegalBlockSizeException,
		javax.crypto.NoSuchPaddingException, java.security.InvalidAlgorithmParameterException, javax.crypto.BadPaddingException {

		// Extract secret key from file
		byte[] keyb = Files.readAllBytes(Paths.get(secKeyFile));
		SecretKeySpec skey = new SecretKeySpec(keyb, "AES");

		SecureRandom srandom = new SecureRandom();
		// Generate iv and save to file
		byte[] iv = new byte[128/8];
		srandom.nextBytes(iv);
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		// Generate cipher
		Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
		ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);

		processFile(ci, originalFile, encryptedFile, iv, true);

	}


	/**
	 * Extracts the secret key from a file, extracts the initialization vector
	 * from the beginning of the encrypted file, uses both secret key and
	 * initialization vector to decrypt the encrypted file data, and writes it to
	 * an output file
	 *
	 * @param  encryptedFile    name of file storing iv and encrypted data
	 * @param  secKeyFile	    name of file storing secret key
	 * @param  outputFile       name of file to write decrypted data to
	 */
	static void decryptFile(String encryptedFile, String secKeyFile, String outputFile)
	 	throws java.io.FileNotFoundException, java.io.IOException, java.security.InvalidKeyException,
		 javax.crypto.IllegalBlockSizeException, java.security.NoSuchAlgorithmException,
		 javax.crypto.NoSuchPaddingException, java.security.InvalidAlgorithmParameterException, javax.crypto.BadPaddingException {

		byte[] iv = new byte[128/8];
		FileInputStream in = new FileInputStream(encryptedFile);
		in.read(iv,0,128/8);
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		byte[] keyb = Files.readAllBytes(Paths.get(secKeyFile));
		SecretKeySpec skey = new SecretKeySpec(keyb, "AES");

		Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
		ci.init(Cipher.DECRYPT_MODE, skey, ivspec);

		processFile(ci, encryptedFile, outputFile, iv, false);

	}

	public static PrivateKey getPrivKey(String filename)
    throws Exception {

    File f = new File(filename);
    FileInputStream fis = new FileInputStream(f);
    DataInputStream dis = new DataInputStream(fis);
    byte[] keyBytes = new byte[(int)f.length()];
    dis.readFully(keyBytes);
    dis.close();

    PKCS8EncodedKeySpec spec =
      new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePrivate(spec);
	}

	public static PublicKey getPubKey(String filename)
    throws Exception {

    File f = new File(filename);
    FileInputStream fis = new FileInputStream(f);
    DataInputStream dis = new DataInputStream(fis);
    byte[] keyBytes = new byte[(int)f.length()];
    dis.readFully(keyBytes);
    dis.close();

    X509EncodedKeySpec spec =
      new X509EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
  }

	static private void processKey(Cipher ci,InputStream in,OutputStream out)
    throws javax.crypto.IllegalBlockSizeException,
           javax.crypto.BadPaddingException,
           java.io.IOException
	{
	    byte[] ibuf = new byte[1024];
	    int len;
	    while ((len = in.read(ibuf)) != -1) {
	        byte[] obuf = ci.update(ibuf, 0, len);
	        if ( obuf != null ) out.write(obuf);
	    }
	    byte[] obuf = ci.doFinal();
	    if ( obuf != null ) out.write(obuf);
	}

	/**
	 * Extracts secret key from a file, encrypts a secret key file using
     * a public Key (*.der) and writes the encrypted secret key to a file
	 *
	 * @param  secKeyFile    name of file holding secret key
	 * @param  pubKeyFile    name of public key file for encryption
	 * @param  encKeyFile    name of file to write encrypted secret key
	 */
	static void encryptKey(String secKeyFile, String pubKeyFile, String encKeyFile)
	 	throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException, java.io.FileNotFoundException,
		 java.io.IOException, javax.crypto.IllegalBlockSizeException, javax.crypto.BadPaddingException,
		 javax.crypto.NoSuchPaddingException, java.lang.Exception {

		PublicKey pubKey = getPubKey(pubKeyFile);

		Cipher ci = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		ci.init(Cipher.ENCRYPT_MODE, pubKey);

		try (FileInputStream in = new FileInputStream(secKeyFile);
		FileOutputStream out = new FileOutputStream(encKeyFile)) {
		    processKey(ci, in, out);
		}

	}


	/**
	 * Decrypts an encrypted secret key file using a private Key (*.der)
	 * and writes the decrypted secret key to a file
	 *
	 * @param  encKeyFile       name of file storing encrypted secret key
	 * @param  privKeyFile      name of private key file for decryption
	 * @param  secKeyFile       name of file to write decrypted secret key
	 */
	static void decryptKey(String encKeyFile, String privKeyFile, String secKeyFile)
		throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException, java.io.FileNotFoundException,
		 java.io.IOException, javax.crypto.IllegalBlockSizeException, javax.crypto.BadPaddingException,
		 javax.crypto.NoSuchPaddingException, java.lang.Exception {

		PrivateKey privKey = getPrivKey(privKeyFile);
		Cipher ci = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		ci.init(Cipher.DECRYPT_MODE, privKey);
		try (FileInputStream in = new FileInputStream(encKeyFile);
		     FileOutputStream out = new FileOutputStream(secKeyFile)) {
		    processKey(ci, in, out);
		}

	}


	/**
	 * Main Program Runner
	 */
	public static void main(String[] args) throws Exception{

		String func;

		if(args.length < 1) {
			func = "";
		} else {
			func = args[0];
		}

		switch(func)
		{
			case "generatekey":
				if(args.length != 2) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr generatekey <key output file>");
					break;
				}
				System.out.println("Generating secret key and writing it to " + args[1]);
				generateKey(args[1]);
				break;
			case "encryptfile":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>");
					break;
				}
				System.out.println("Encrypting " + args[1] + " with key " + args[2] + " to "  + args[3]);
				encryptFile(args[1], args[2], args[3]);
				break;
			case "decryptfile":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>");
					break;
				}
				System.out.println("Decrypting " + args[1] + " with key " + args[2] + " to " + args[3]);
				decryptFile(args[1], args[2], args[3]);
				break;
			case "encryptkey":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file>");
					break;
				}
				System.out.println("Encrypting key file " + args[1] + " with public key file " + args[2] + " to " + args[3]);
				encryptKey(args[1], args[2], args[3]);
				break;
			case "decryptkey":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>");
					break;
				}
				System.out.println("Decrypting key file " + args[1] + " with private key file " + args[2] + " to " + args[3]);
				decryptKey(args[1], args[2], args[3]);
				break;
			default:
				System.out.println("Invalid Arguments.");
				System.out.println("Usage:");
				System.out.println("  Cryptr generatekey <key output file>");
				System.out.println("  Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>");
				System.out.println("  Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>");
				System.out.println("  Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file> ");
				System.out.println("  Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>");
		}

		System.exit(0);

	}

}
