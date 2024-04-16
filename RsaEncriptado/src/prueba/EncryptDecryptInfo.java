package prueba;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;


public class EncryptDecryptInfo {
	
	public final static int AES_KEY_SIZE = 128;
	public final static int AES_IV_LENGTH = 12;
	public final static int AES_TAG_LENGTH = 16;
    private static SecretKeySpec secretKey;
    private static byte[] key;

	public static byte[] GenerateIV() throws Exception
	{
		byte[] IV = null;
		try{
			// Generate IV
			IV = new byte[AES_IV_LENGTH];
		    SecureRandom random = new SecureRandom();
		    random.nextBytes(IV);
		    
		}catch(Exception e){
			System.err.println("ERROR BILLETERA MOVIL" + "\n"
					+ "Tokenization.java===> GenerateIV: ERROR BILLETERA MOVIL====>" + e.toString());
			System.out.println("ERROR BILLETERA MOVIL" + "\n"
					+ "Tokenization.java===> GenerateIV: ERROR BILLETERA MOVIL====>" + e.toString());
		}
		return IV;
	}
	public static byte[] GenerateKey() throws Exception
	{
		byte[] key = null;
		try{
			// Generate Key
		     KeyGenerator keygen = KeyGenerator.getInstance("AES") ; // key generator to be used with AES algorithm.
		     keygen.init(AES_KEY_SIZE) ; // Key size is specified here.
		     key = keygen.generateKey().getEncoded();
		}catch(Exception e){
			 e.printStackTrace();
				System.err.println("ERROR BILLETERA MOVIL" + "\n"
						+ "Tokenization.java===> GenerateKey: ERROR BILLETERA MOVIL====>" + e.toString());
				System.out.println("ERROR BILLETERA MOVIL" + "\n"
						+ "Tokenization.java===> GenerateKey: ERROR BILLETERA MOVIL====>" + e.toString());
		}
		
	     return key;
	}
	
	public static byte[] encryptGCM(byte[] plaintext, byte[] key, byte[] IV, int AES_TAG_LENGTH) throws Exception
    {
		byte[] cipherText = null;
		try{
	        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
	        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
	        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AES_TAG_LENGTH * 8, IV);
	        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
	        cipherText = cipher.doFinal(plaintext);
		}catch (Exception  e) {
			e.printStackTrace();
			System.err.println("ERROR BILLETERA MOVIL" + "\n"
					+ "Tokenization.java===> encryptGCM: ERROR BILLETERA MOVIL====>" + e.toString());
			System.out.println("ERROR BILLETERA MOVIL" + "\n"
					+ "Tokenization.java===> encryptGCM: ERROR BILLETERA MOVIL====>" + e.toString());
		} 
        return cipherText;
    }
	
	public static String decryptGCM(byte[] cipherText, byte[] key, byte[] IV, int AES_TAG_LENGTH) throws Exception
    {
    	byte[] decryptedText = null;
		try{
	        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
	        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
	        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AES_TAG_LENGTH * 8, IV);
	        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
	        decryptedText = cipher.doFinal(cipherText);
		}catch(Exception e){
			e.printStackTrace();
			System.err.println("ERROR BILLETERA MOVIL" + "\n"
					+ "Tokenization.java===> decryptGCM: ERROR BILLETERA MOVIL====>" +e.getMessage());
			System.out.println("ERROR BILLETERA MOVIL" + "\n"
					+ "Tokenization.java===> decryptGCM: ERROR BILLETERA MOVIL====>" + e);
		}
		
        return new String(decryptedText);
    }
    
    public static   byte[] ccmEncrypt( byte[] keyBytes, byte[] nonce, byte[] testInput, int AES_TAG_LENGTH) throws GeneralSecurityException
	{
    	byte[] cipherText = null;
    	try{	
    		Security.addProvider(new BouncyCastleProvider());
    		GCMParameterSpec parameterSpec = new GCMParameterSpec(AES_TAG_LENGTH * 8, nonce);
    		Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
    		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
    		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, parameterSpec);
    		cipherText = cipher.doFinal(testInput);
    		//System.out.println(DatatypeConverter.printHexBinary(cipher.doFinal(testInput)));
    	}catch(Exception e){
			e.printStackTrace();
			System.err.println("ERROR BILLETERA MOVIL" + "\n"
					+ "Tokenization.java===> ccmEncrypt: ERROR BILLETERA MOVIL====>" + e.toString());
			System.out.println("ERROR BILLETERA MOVIL" + "\n"
					+ "Tokenization.java===> ccmEncrypt: ERROR BILLETERA MOVIL====>" + e.toString());
		}
    	
		return cipherText;
	}
	
	public static  String ccmDecrypt( byte[] keyBytes, byte[] nonce, byte[] testInput, int AES_TAG_LENGTH) throws GeneralSecurityException
	{
		byte[] decryptedText = null;
    	try{
    		Security.addProvider(new BouncyCastleProvider());
    		GCMParameterSpec parameterSpec = new GCMParameterSpec(AES_TAG_LENGTH * 8, nonce);
    		Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
    		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
    		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, parameterSpec);
    		decryptedText = cipher.doFinal(testInput);
    		//System.out.println(new String(cipher.doFinal(testInput)));
    	}catch(Exception e){
			e.printStackTrace();
			System.err.println("ERROR BILLETERA MOVIL" + "\n"
					+ "Tokenization.java===> ccmDecrypt: ERROR BILLETERA MOVIL====>" + e.toString());
			System.out.println("ERROR BILLETERA MOVIL" + "\n"
					+ "Tokenization.java===> ccmDecrypt: ERROR BILLETERA MOVIL====>" + e.toString());
		}
    	
		return new String(decryptedText);
	}
    
	 public static byte[] ccmEncrypt1( byte[] keyBytes, byte[] nonce, byte[] testInput, int AES_TAG_LENGTH) throws GeneralSecurityException
		{
	    	byte[] cipherText = null;
	    	try{	
	    		Security.addProvider(new BouncyCastleProvider());
	    		//GCMParameterSpec parameterSpec = new GCMParameterSpec(AES_TAG_LENGTH * 8, nonce);
	    		IvParameterSpec parameterSpec = new IvParameterSpec(nonce);
	    		Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
	    		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
	    		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, parameterSpec);
	    		cipherText = cipher.doFinal(testInput);
	    		//System.out.println(DatatypeConverter.printHexBinary(cipher.doFinal(testInput)));
	    	}catch(Exception e){
	    		e.printStackTrace();
				System.out.println("Error al encriptar informacion: " + e.toString());
			}
	    	
			return cipherText;
		}
	 
		public static  String ccmDecrypt1( byte[] keyBytes, byte[] nonce, byte[] testInput, int AES_TAG_LENGTH) throws GeneralSecurityException
		{
			byte[] decryptedText = null;
	    	try{
	    		Security.addProvider(new BouncyCastleProvider());
	    		//GCMParameterSpec parameterSpec = new GCMParameterSpec(AES_TAG_LENGTH * 8, nonce);
	    		IvParameterSpec parameterSpec = new IvParameterSpec(nonce);
	    		Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
	    		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
	    		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, parameterSpec);
	    		decryptedText = cipher.doFinal(testInput);
	    		//System.out.println(new String(cipher.doFinal(testInput)));
	    	}catch(Exception e){
	    		e.printStackTrace();
				System.out.println("Error al desencriptar informacion: " + e.toString());
			}
	    	
			return new String(decryptedText);
		}
	 public static   byte[] cbcEncrypt( byte[] keyBytes, byte[] nonce, byte[] testInput, int AES_TAG_LENGTH) throws GeneralSecurityException
		{
	    	byte[] cipherText = null;
	    	try{	
	    		
	    		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
	    		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
	    		cipherText = cipher.doFinal(testInput);
	    		//System.out.println(DatatypeConverter.printHexBinary(cipher.doFinal(testInput)));
	    	}catch(Exception e){
	    		e.printStackTrace();
				System.err.println("ERROR BILLETERA MOVIL" + "\n"
						+ "Tokenization.java===> cbcEncrypt: ERROR BILLETERA MOVIL====>" + e.toString());
				System.out.println("ERROR BILLETERA MOVIL" + "\n"
						+ "Tokenization.java===> cbcEncrypt: ERROR BILLETERA MOVIL====>" + e.toString());
			}
	    	
			return cipherText;
		}
	 
	 public static  String cbcDecrypt( byte[] keyBytes, byte[] nonce, byte[] testInput, int AES_TAG_LENGTH) throws GeneralSecurityException
		{
			byte[] decryptedText = null;
	    	try{
	    	
	    		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
	    		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
	    		decryptedText = cipher.doFinal(testInput);
	    		//System.out.println(new String(cipher.doFinal(testInput)));
	    	}catch(Exception e){
	    		e.printStackTrace();
	    		System.err.println("ERROR BILLETERA MOVIL" + "\n"
						+ "Tokenization.java===> cbcDecrypt: ERROR BILLETERA MOVIL====>" + e.toString());
				System.out.println("ERROR BILLETERA MOVIL" + "\n"
						+ "Tokenization.java===> cbcDecrypt: ERROR BILLETERA MOVIL====>" + e.toString());
			}
	    	
			return new String(decryptedText);
		}
	 public static void ecbSetKey(String myKey) 
	    {
	        MessageDigest sha = null;
	        try {
	            key = myKey.getBytes("UTF-8");
	            sha = MessageDigest.getInstance("SHA-1");
	            key = sha.digest(key);
	            key = Arrays.copyOf(key, 16); 
	            secretKey = new SecretKeySpec(key, "AES");
	        } 
	        catch (NoSuchAlgorithmException e) {
	            e.printStackTrace();
	        } 
	        catch (UnsupportedEncodingException e) {
	            e.printStackTrace();
	        }
	    }
	 
	 public static String ecbEncrypt(String strToEncrypt, String secret) 
	    {
	        try
	        {
	            ecbSetKey(secret);
	            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
	        } 
	        catch (Exception e) 
	        {
	        	e.printStackTrace();
	        	System.err.println("ERROR BILLETERA MOVIL" + "\n"
						+ "Tokenization.java===> ecbEncrypt: ERROR BILLETERA MOVIL====>" + e.toString());
				System.out.println("ERROR BILLETERA MOVIL" + "\n"
						+ "Tokenization.java===> ecbEncrypt: ERROR BILLETERA MOVIL====>" + e.toString());
	        }
	        return null;
	    }
	 
	 public static String ecbDecrypt(String strToDecrypt, String secret) 
	    {
	        try
	        {
	            ecbSetKey(secret);
	            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
	            cipher.init(Cipher.DECRYPT_MODE, secretKey);
	            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
	        } 
	        catch (Exception e) 
	        {
	        	e.printStackTrace();
	        	System.err.println("ERROR BILLETERA MOVIL" + "\n"
						+ "Tokenization.java===> ecbDecrypt: ERROR BILLETERA MOVIL====>" + e.toString());
				System.out.println("ERROR BILLETERA MOVIL" + "\n"
						+ "Tokenization.java===> ecbDecrypt: ERROR BILLETERA MOVIL====>" + e.toString());
	        }
	        return null;
	    }
	 
    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1)
            return null;
        byte[] result = new byte[hexStr.length()/2];
        for (int i = 0;i< hexStr.length()/2; i++) {
            int high = Integer.parseInt(hexStr.substring(i*2, i*2+1), 16);
            int low = Integer.parseInt(hexStr.substring(i*2+1, i*2+2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }
    
	public static String toHexString(byte[] array) {
	    return DatatypeConverter.printHexBinary(array);
	}

	public static byte[] toByteArray(String s) {
	    return DatatypeConverter.parseHexBinary(s);
	}
	
	public static byte[] toByteArray(InputStream in) throws IOException {
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		int len;
		// read bytes from the input stream and store them in buffer
		while ((len = in.read(buffer)) != -1) {
			// write bytes from the buffer into output stream
			os.write(buffer, 0, len);
		}
		return os.toByteArray();
	}
}
