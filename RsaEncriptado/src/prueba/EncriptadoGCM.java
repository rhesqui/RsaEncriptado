package prueba;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class EncriptadoGCM { 
    static String plainText = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";
    public final static int AES_KEY_SIZE = 128;
    public final static int GCM_IV_LENGTH = 12;
    public final static int GCM_TAG_LENGTH = 16;
    static InputStream is = null;
	static Properties properties = new Properties();
	static String urlApiInbound = null;

 
	public static void main(String[] args) throws Exception {
	    String keyString =  "404142434445464748494A4B4C4D4E4F4F4E4D4C4B4A49484746454443424140";
	    String keyDinamic = "yHLwEN0QmNaYC1jrJI/R0yDApTrk44m4xrcCUKFv8neS4tLO3ML3AZ++yihCaGaY";
		
	    String letrasNumeros ="ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	    EncryptDecryptInfo encryptInfo = new EncryptDecryptInfo();
	    String finalyKey = encryptInfo.ecbDecrypt(keyDinamic, keyString);
	    
	    System.out.println("finaly key "+finalyKey);
	    
	    byte[] Key = DatatypeConverter.parseHexBinary(finalyKey);	
	    
//	    System.out.println("cantidad "+letrasNumeros.length());
	    //encrypt
//	    Credito String decrypt =  "{\"CVV2\":\"365\",\"cardholderName\":\"PRUEBAS BM\",\"PAN\":\"4390750001683879\",\"expirationDate\":{\"month\":\"12\",\"year\":\"2028\"}}";
//		debito String decrypt = "{\"cardholderName\":\"OCHOA JOVEL JAVIER VLADIM\",\"PAN\":\"4118410005622925\",\"expirationDate\":{\"month\":\"07\",\"year\":\"2025\"}}";
//	    String decrypt = "{\"CVV2\":\"365\",\"cardholderName\":\"PRUEBAS BM\",\"PAN\":\"4390750001683879\",\"expirationDate\":{\"month\":\"12\",\"year\":\"2028\"}}";
	    String decrypt = "{\"CVV2\":\"114\",\"cardholderName\":\"PRUEBAS BM\",\"PAN\":\"4390750001302496\",\"expirationDate\":{\"month\":\"12\",\"year\":\"2028\"}}";
	    byte[] IV = encryptInfo.GenerateIV();		
	    System.out.println("IV Text : " + encryptInfo.toHexString(IV));
	    byte[] encryptedData = encryptInfo.encryptGCM(decrypt.getBytes(), Key, IV, 16);
	    System.out.println("BASE64 Encrypted Text : " + Base64.getEncoder().encodeToString(encryptedData));
	    
	   // decrypt
	    String IVStrEncrypt = "E446391123D7E428729D5256";
	    String MACLengthStrEncrypt = "16";
	    String CardtextEncrip = "KqJ/v32sPFQPGq5XJpxnxnxvo3jBB3n5uNoMkVuRbBy914C7rpOYYNCE+aaKcgXEyvM9m49BEVxONn5YbMjYJoqwmJTGaGH2COdo8SKsKKh8T+7xWPeu0a8Z1stKua/kjn4HA3IHrcXHZObd/AHv88Lc4LW6fZYvLPUdrm2obuuFpsSVwa8/EM12zxMPvW93y3K1EElYqBTl4ttsXSMfn0VJSUym8tqQI39pMnuwXTzyjtWAdfvUQevBIlT0dPXvqVJXPn/VQbfJkz6PgoZe8hr8JoJ7vly6E0FW4wG2efRMYSZr+qDFIYFXNsoUV++nMvsV8Vvf2oqs2lYV0jg=";
	    byte[] IVEncrypt = DatatypeConverter.parseHexBinary(IVStrEncrypt);
	    byte[] textInputBytes = Base64.getDecoder().decode(CardtextEncrip);
	    int MACLength = Integer.parseInt(MACLengthStrEncrypt);
	    String decryptedCard = EncryptDecryptInfo.decryptGCM(textInputBytes, Key, IVEncrypt, MACLength);
	    System.out.println("decrypted Text : " + decryptedCard);
	    
	  String tokenEncrypt = "{\"tokenStatus\":\"ACTIVE\",\"state\":\"ACTIVE\",\"tokenRefID\":\"DNITHE413226560014573306\",\"type\":\"COF\",\"tokenType\":\"COF\",\"deviceInfo\":{\"deviceType\":\"MOBILE_PHONE\",\"idDevice\":\"000000000000000000003201\",\"deviceID\":\"000000000000000000003201\",\"deviceName\":\"c2Ftc3VuZyBrb26h\",\"deviceNumber\":\"4421987654422\"},\"expirationDate\":{\"month\":\"09\",\"year\":\"2027\"},\"token\":\"4531098634634311\"}";  
	  byte[] IVToken = encryptInfo.GenerateIV();		
	  System.out.println("IV Text token : " + encryptInfo.toHexString(IVToken));
	  byte[] encryptedDataToken = encryptInfo.encryptGCM(tokenEncrypt.getBytes(), Key, IVToken, 16);
	  System.out.println("BASE64 Encrypted Text  token: " + Base64.getEncoder().encodeToString(encryptedDataToken));  
	    
	}
	    
	
	public static byte[] encrypt(byte[] plaintext, byte[] key, byte[] IV) throws Exception
    {
		byte[] cipherText = null;
		try{
			  // Get Cipher Instance
	       // Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
	        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding");
	        // Create SecretKeySpec
	        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
	        // Create GCMParameterSpec
	        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
	        
	        // Initialize Cipher for ENCRYPT_MODE
	       // cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
	        
	        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(IV));
	        // Perform Encryption
	        cipherText = cipher.doFinal(plaintext);
	        
		}catch(Exception e){
			 System.out.println("Error al encriptar informacion: " + e.toString());
		}
      
        return cipherText;
    }
	public static byte[] GenerateIV() throws Exception
	{
		byte[] IV = null;
		try{
			// Generate IV
			IV = new byte[GCM_IV_LENGTH];
		    SecureRandom random = new SecureRandom();
		    random.nextBytes(IV);
		    
		}catch(Exception e){
			 System.out.println("Error al generar IV: " + e.toString());
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
			 System.out.println("Error al generar Key: " + e.toString());
		}
		
	     return key;
	}
    public static String decrypt(byte[] cipherText, byte[] key, byte[] IV) throws Exception
    {
    	byte[] decryptedText = null;
		try{
			 // Get Cipher Instance
	       // Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
	        
	        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding");
	        // Create SecretKeySpec
	        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
	        // Create GCMParameterSpec
	        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
	        // Initialize Cipher for DECRYPT_MODE
	        // cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
	        
	        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(IV));
	        // Perform Decryption
	        decryptedText = cipher.doFinal(cipherText);
		}catch(Exception e){
			System.out.println("Error al desencriptar informacion: " + e.toString());
		}
        return new String(decryptedText);
    }
	
	public static String toHexString(byte[] array) {
	    return DatatypeConverter.printHexBinary(array);
	}

	public static byte[] toByteArray(String s) {
	    return DatatypeConverter.parseHexBinary(s);
	}
	
	public static String ecbDecrypt(String yaleDinamic, String secretKey)throws Exception {
		SecretKeySpec secretSpec;
		MessageDigest sha;
		
		byte[] key = secretKey.getBytes(StandardCharsets.UTF_8);
		sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16); 
        secretSpec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretSpec);
        return new String(cipher.doFinal(Base64.getDecoder().decode(yaleDinamic)));
		
	}
}
