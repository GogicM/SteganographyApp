package crypto;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/*
 * Class that contains asymmetric and symmetric cryptography methods
 */
public class Crypto {

    private Cipher asymmCipher;
    //one cipher for asymmetric and one for symmetric
    private Cipher symmCipher;

    public IvParameterSpec iv;
    SecureRandom sr;
    KeyGenerator kg;

    public Crypto() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.asymmCipher = Cipher.getInstance("RSA");
        //Changed from CBC to ECB, had problems with iv for CBC
        this.symmCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

    }

    /*
	        Method for getting private key from file system
	        Need to convert private key to pkcs8 format in order to read them in java
	        Keys need to be in der format
     */
    public PrivateKey getPrivateKey(String filename) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {

        File file = new File(filename);
        DataInputStream dis = new DataInputStream(new FileInputStream(file));
        byte[] privKey = new byte[(int) file.length()];
        dis.readFully(privKey);
        dis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);

    }

    /*
	        Method for getting private key from file system
	        Need to convert public key to X509 format in order to read them in java
	        Keys need to be in der format
     */
    public PublicKey getPublicKey(String filename) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {

        File file = new File(filename);
        DataInputStream dis = new DataInputStream(new FileInputStream(file));
        byte[] pubKey = new byte[(int) file.length()];
        dis.readFully(pubKey);
        dis.close();

        X509EncodedKeySpec spec = new X509EncodedKeySpec(pubKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);

    }

    /*
	        Method for symmetric encription of file
     */
    public byte[] SymmetricFileEncryption(byte[] file, SecretKey key)
            throws InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException {

        this.symmCipher.init(Cipher.ENCRYPT_MODE, key);
        return this.symmCipher.doFinal(file);
    }

    /*
	        Method for symmetric decription of file
     */
    public byte[] SymmetricFileDecription(byte[] file, SecretKey key)
            throws InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException {

        this.symmCipher.init(Cipher.DECRYPT_MODE, key);
        return this.symmCipher.doFinal(file);
    }

    /*
	        Method for asymmetric encription of file
     */
    public byte[] AsymmetricFileEncription(byte[] file, PublicKey pubKey)
            throws IOException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {

        this.asymmCipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return this.asymmCipher.doFinal(file);
    }

    /*
	        Method for asymmetric decription of file
     */
    public byte[] AsymmetricFileDecription(byte[] file, PrivateKey privKey)
            throws IOException, GeneralSecurityException {
        this.asymmCipher.init(Cipher.DECRYPT_MODE, privKey);
        return this.asymmCipher.doFinal(file);
    }

    /*
	        Method for write encrypted file
     */
    public void writeToFile(File output, byte[] data, SecretKey key, boolean append)
            throws IllegalBlockSizeException, BadPaddingException, 
            IOException, InvalidKeyException, NoSuchAlgorithmException {
        
        FileOutputStream fos; 
        if(!append ) { 
        	fos = new FileOutputStream(output);
        } else {
        	fos = new FileOutputStream(output, append);
        }
        byte[] encContent = SymmetricFileEncryption(data, key);
        fos.write(encContent);
        fos.flush();
        fos.close();
    }
    /*
	        Method for read from file
     */    

   public byte[] readFromFile(File input, SecretKey key)
            throws IllegalBlockSizeException, BadPaddingException, 
            IOException, InvalidKeyException, NoSuchAlgorithmException, 
            InvalidAlgorithmParameterException, GeneralSecurityException {
        
        byte[] fileContent = new byte[(int) input.length()];
        FileInputStream fis = new FileInputStream(input);
        fis.read(fileContent);
        fis.close();
        
        return SymmetricFileDecription(fileContent, key);
    }

    /*
	        Method for string (message) encryption with symmetric key
     */
    public String EncryptStringSymmetric(String message, SecretKey key)
            throws InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {

        String encryptedData = null;
        this.symmCipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(symmCipher.doFinal(message.getBytes()));

    }

    /*
	        Method for decription of string (message)encrypted with symmetric algorithm
     */
    public String DecryptStringSymmetric(String message, SecretKey key)
            throws InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, IOException {

        String decryptedData = null;

        this.symmCipher.init(Cipher.DECRYPT_MODE, key);
        return new String(symmCipher.doFinal(Base64.getDecoder().decode(message)));
    }
    
    /*
    	Method for string array  encryption with symmetric algorithm
    */
    public String[] EncryptStringArraySymmetric(String[] array, SecretKey key)
    		throws InvalidKeyException, IllegalBlockSizeException,
    		BadPaddingException {
    	
//    	if(array == null) {
//    		System.out.println("ARRAY IS NULL");
//    	}

    	String[] encryptedArray = new String[array.length];
    	this.symmCipher.init(Cipher.ENCRYPT_MODE, key);
    	for(int i = 0; i < array.length; i++) {
    		encryptedArray[i] = Base64.getEncoder().encodeToString(symmCipher.doFinal(array[i].getBytes()));
    	}
    	return encryptedArray;

    }

	/*
	    Method for decription of string array encrypted with symmetric algorithm
	*/
	public String[] DecryptStringArraySymmetric(String[] encryptedArray, SecretKey key)
	    throws InvalidKeyException, IllegalBlockSizeException,
	    BadPaddingException, IOException {
	
		String[] decryptedArray = new String[encryptedArray.length];
		
		this.symmCipher.init(Cipher.DECRYPT_MODE, key);
		for(int i = 0; i < encryptedArray.length; i++) {
			decryptedArray[i] = new String(symmCipher.doFinal(Base64.getDecoder().decode(encryptedArray[i])));
		}
		return decryptedArray;
	}

    public String EncryptStringAsymmetric(String message, PublicKey key)
            throws InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {
        this.asymmCipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(asymmCipher.doFinal(message.getBytes()));
    }

    public String DecryptStringAsymmetric(String encMessage, PrivateKey key)
            throws InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {

        this.asymmCipher.init(Cipher.DECRYPT_MODE, key);
        return new String(asymmCipher.doFinal(Base64.getDecoder().decode(encMessage)));
    }
    
    public String[] EncryptStringArrayAsymmetric(String[] message, PublicKey key)
            throws InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {
    	String[] encryptedArray = new String[message.length];

        this.asymmCipher.init(Cipher.ENCRYPT_MODE, key);
        for(int i = 0; i < message.length; i++) {
    		encryptedArray[i] = Base64.getEncoder().encodeToString(asymmCipher.doFinal(message[i].getBytes()));
    	}
    	return encryptedArray;
    }

    public String[] DecryptStringArrayAsymmetric(String[] encMessage, PrivateKey key)
            throws InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {
		String[] decryptedArray = new String[encMessage.length];
        this.asymmCipher.init(Cipher.DECRYPT_MODE, key);
		for(int i = 0; i < encMessage.length; i++) {
			decryptedArray[i] = new String(asymmCipher.doFinal(Base64.getDecoder().decode(encMessage[i])));
		}
		return decryptedArray;
    }

    public X509Certificate getCertificate(String path) throws CertificateException,
            FileNotFoundException {

        X509Certificate certificate = null;

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(path);
        certificate = (X509Certificate) cf.generateCertificate(fis);

        return certificate;
    }

    public String encodeWithSHA256(String message) throws NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        String encoded = Base64.getEncoder().encodeToString(hash);

        return encoded;
    }

    public String signMessagge(String message, PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidKeyException, InvalidKeySpecException, IOException, SignatureException {

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(message.getBytes());
        byte[] signature = sig.sign();	
        return Base64.getEncoder().encodeToString(signature);

    }

    public boolean verifyDigitalSignature(String data, String signature, PublicKey publicKey)
            throws GeneralSecurityException, IOException {

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data.getBytes());
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return sig.verify(sigBytes);
    }
}
