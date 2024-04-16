package prueba;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.json.JSONArray;
import org.json.JSONObject;


import java.util.Base64;
import java.util.Random;


public class encrypGCMV2 {
	private static SecretKeySpec secretKey;
	
	static int[] myArray = {1,2,9,2,5,3,5,1,5};

	public static void main(String[] args) throws Exception {
	
/*
		
		  KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		  SecureRandom secureRandom = new SecureRandom();
		  keyPairGenerator.initialize(2048, secureRandom); 
		  KeyPair pair =  keyPairGenerator.generateKeyPair(); 
		  PublicKey publicKey = pair.getPublic();
		  String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		  System.out.println("public key = " + publicKeyString); 
		  PrivateKey privateKey  = pair.getPrivate(); 
		  String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
		   System.out.println("private key = " + privateKeyString); 
		  //Encrypt Helloworld message 
		  Cipher encryptionCipher = Cipher.getInstance("RSA");
		  encryptionCipher.init(Cipher.ENCRYPT_MODE, privateKey); 
		  //String message = "{\"cvv2\":\"123\"}"; 
		  String message = "Prueba"; 
		  byte[] encryptedMessage =  encryptionCipher.doFinal(message.getBytes());
		  String encryption = Base64.getEncoder().encodeToString(encryptedMessage);
		  System.out.println("encrypted message = " + encryption); 
		  //Decrypt Hello world message 
		  Cipher decryptionCipher = Cipher.getInstance("RSA");
		  decryptionCipher.init(Cipher.DECRYPT_MODE, publicKey); byte[]
		  decryptedMessage = decryptionCipher.doFinal(encryptedMessage); 
		  String decryption = new String(decryptedMessage);
		  System.out.println("decrypted message = " + decryption);
*/

		String keyEncriptado = EncryptDecryptInfo.ecbDecrypt("yHLwEN0QmNaYC1jrJI/R0yDApTrk44m4xrcCUKFv8neS4tLO3ML3AZ++yihCaGaY",
				"404142434445464748494A4B4C4D4E4F4F4E4D4C4B4A49484746454443424140");

		byte[] key = DatatypeConverter.parseHexBinary(keyEncriptado);
		String encriptadoToken = "X9XrPK4UxEQCP6Bjc6kKeR3hO4Q00LWLeIdrugDFpTr866RzqGDWvXjIrtVKjkDFxp7mSjuGYrjjg1Sk3xW/BhjSKFCfVKujLGktnApJMUA4qPOv10ZhuL3LSJ6F8SA1Lzlh3sFUX6GYCHHG6qM9olMs47WZETbhksA9vXK3j46+52NQew==";
		String ivEncriptado = "3E5622F03AD16A86538E6CB1";
		byte[] descodificado = Base64.getDecoder().decode(encriptadoToken);
		byte[] IV = DatatypeConverter.parseHexBinary(ivEncriptado);

		Integer macLength = 16;
		String desencriptadoToken = EncryptDecryptInfo.decryptGCM(descodificado, key, IV, macLength);
		JSONArray array = new JSONArray(desencriptadoToken);
		int i = array.length();
		System.out.println(desencriptadoToken);
		for(int j=0;j<i;j++) {
			JSONObject obj = array.getJSONObject(j);
			byte[] ivEncript = EncryptDecryptInfo.GenerateIV();
			String cardStrn = obj.toString();
			byte[] encriptado = EncryptDecryptInfo.encryptGCM(cardStrn.getBytes(), key, ivEncript, 16);
			
			System.out.println("IV "+ j+" token " + EncryptDecryptInfo.toHexString(ivEncript));
			System.out.println("info token "+ j+" encriptado " + Base64.getEncoder().encodeToString(encriptado));
			System.out.println("\n");
		}
		

			System.out.println("\n");
			System.out.println("\n");
			System.out.println("\n");
			Random rdn = new Random();
			
			for(int k=0;k<i;k++){
				Long numTokenRef = (long)(rdn.nextDouble() * 999999999999999L);
				Long numToken =  (long)(rdn.nextDouble() * 999999999999999L);; //+ 1000000000000000L;
				String tokenRefId ="DNITHE".concat(String.valueOf(numTokenRef));
				System.out.println("Token ref de regitro "+k+" "+tokenRefId);
				System.out.println("Token del registro "+k+" "+numToken);
				JSONObject jsonToken = new JSONObject("{\"tokenStatus\":\"ACTIVE\",\"state\":\"ACTIVE\",\"tokenRefID\":\""+tokenRefId+"\",\"type\":\"HCE\",\"tokenType\":\"HCE\",\"deviceInfo\":{\"deviceType\":\"MOBILE_PHONE\",\"idDevice\":\"000000000000000000003212\",\"deviceID\":\"000000000000000000003212\",\"deviceName\":\"c2Ftc3VuZyXLX30h\",\"deviceNumber\":\"0000000000011\"},\"expirationDate\":{\"month\":\"12\",\"year\":\"2030\"},\"token\":\""+String.valueOf(numToken)+"\"}");
				byte[] ivEncriptToken = EncryptDecryptInfo.GenerateIV();
				String tokenNew = jsonToken.toString();
				byte[] encrypNuevoToken = EncryptDecryptInfo.encryptGCM(tokenNew.getBytes(), key, ivEncriptToken, 16);
				System.out.println("IV "+k+"  "+ EncryptDecryptInfo.toHexString(ivEncriptToken));
				System.out.println("info token encriptado numero "+k+" "+ Base64.getEncoder().encodeToString(encrypNuevoToken));
				System.out.println("\n");
				System.out.println("\n");
				
			}
			
			JSONObject jsonToken = new JSONObject("{\"tokenStatus\":\"ACTIVE\",\"state\":\"ACTIVE\",\"tokenRefID\":\"DNITHE413226561924553243\",\"type\":\"HCE\",\"tokenType\":\"HCE\",\"deviceInfo\":{\"deviceType\":\"MOBILE_PHONE\",\"idDevice\":\"000000000000000000003212\",\"deviceID\":\"000000000000000000003212\",\"deviceName\":\"c2Ftc3VuZyXLX30h\",\"deviceNumber\":\"0000000000011\"},\"expirationDate\":{\"month\":\"12\",\"year\":\"2030\"},\"token\":\"9062617855364061\"}");
			byte[] ivEncriptToken = EncryptDecryptInfo.GenerateIV();
			String tokenNew = jsonToken.toString();
			byte[] encrypNuevoToken = EncryptDecryptInfo.encryptGCM(tokenNew.getBytes(), key, ivEncriptToken, 16);
			
			
	
			
			String encriptadoToken2 = "X9XrPK4UxEQCP6Bjc6kKeR3hO4Q00LWLeIdrugDFpTr866RzqGDWvXjIrtVKjkDFxp7mSjuGYrjjg1Sk3xW/BhjSKFCfVKujLGktnApJMUA4qPOv10ZhuL3LSJ6F8SA1Lzlh3sFUX6GYCHHG6qM9olMs47WZETbhksA9vXK3j46+52NQew==";
			String ivEncriptado2 = "3E5622F03AD16A86538E6CB1";
			byte[] descodificado2 = Base64.getDecoder().decode(encriptadoToken2);
			byte[] IV2 = DatatypeConverter.parseHexBinary(ivEncriptado2);

			String desencriptadoToken2 = EncryptDecryptInfo.decryptGCM(descodificado2, key, IV2, macLength);
			//System.out.println(desencriptadoToken2);
	
	}
	


}
