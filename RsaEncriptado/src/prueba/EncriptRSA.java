package prueba;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.xml.bind.DatatypeConverter;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;

public class EncriptRSA {

	private static final String HEADER_CTY = "cty";
	private static final String CONTENT_TYPE_JWE = "JWE";

	private KeyFactory keyFactory= null;
		
	/**
	 * Inicializa la variable KeyFactor, es la que se encarga de usar el cifrado
	 * que se tiene que usar para encriptar
	 * @throws Exception
	 */
	private void inicializar() throws Exception {
		this.keyFactory = KeyFactory.getInstance("RSA");

	}

	/**
	 * Genera una llave privada, que pueda leer java y se pueda usar para encriptar 
	 * la informacion
	 * @return PrivateKey 
	 * @throws Exception
	 */
	private PrivateKey generateKeyPrivate(String privateKey) throws Exception {
		PKCS8EncodedKeySpec publicKeySpec = new PKCS8EncodedKeySpec(DatatypeConverter.parseBase64Binary(privateKey));
		return this.keyFactory.generatePrivate(publicKeySpec);
	}

	/**
	 * lee llave publica con la que se puede leer en java y se puede usar para desencriptar
	 * @return publicKey
	 * @throws Exception
	 */
	private PublicKey generateKeyPublic(String publicKey) throws Exception {
		
		X509EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(DatatypeConverter.parseBase64Binary(publicKey));
		return this.keyFactory.generatePublic(privateKeySpec);
	}

	/**
	 * Funcion que encripta la informacion en claro con una firma digital
	 * @param data
	 * @param privateKey
	 * @param publicKey
	 * @return 
	 * @throws Exception
	 */
	private String generateJweJws(String data, RSAPrivateKey privateKey, RSAPublicKey publicKey) throws Exception {
		String kid = UUID.randomUUID().toString();
		Map<String, Object> jweHeaders = new HashMap<>();
		jweHeaders.put("iat", System.currentTimeMillis());

		String jwe = createJwe(data, kid, publicKey, JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, jweHeaders);
		Map<String, Object> jwsHeaders = new HashMap<>();
		long iat = System.currentTimeMillis() / 1000;
		Long exp = iat + 120;
		String signingKid = UUID.randomUUID().toString();
		jwsHeaders.put("iat", iat);
		jwsHeaders.put("exp", exp);
		String jws = createJws(jwe, signingKid, privateKey, jwsHeaders);
		return jws;
	}
	/**
	 * Crea la firma digital para que el cliente
	 * @param jwe
	 * @param kidJws
	 * @param privateKey
	 * @param additionalHeaders
	 * @return
	 * @throws Exception
	 */
	
	private String createJws(String jwe, String kidJws, RSAPrivateKey privateKey, Map<String, Object> additionalHeaders)
			throws Exception {
		JWSObject jwsObject = new JWSObject((new JWSHeader.Builder(JWSAlgorithm.PS256))
												.type(JOSEObjectType.JOSE)
												.keyID(kidJws).contentType(CONTENT_TYPE_JWE)
												.customParams(additionalHeaders).build(), 
											new Payload(jwe));
		JWSSigner signer = new RSASSASigner(privateKey);
		jwsObject.sign(signer);
		return jwsObject.serialize();
	}

	/**
	 * Crea la data encriptada con sus header
	 * @param data
	 * @param kid
	 * @param publicKey
	 * @param jweAlgorithm
	 * @param encryptionMethod
	 * @param aditionalHeaders
	 * @return
	 * @throws Exception
	 */
	private String createJwe(String data, String kid, RSAPublicKey publicKey, JWEAlgorithm jweAlgorithm,
			EncryptionMethod encryptionMethod, Map<String, Object> aditionalHeaders) throws Exception {
		JWEHeader jweHeader = header(kid, jweAlgorithm, encryptionMethod, aditionalHeaders);
		JWEObject jweObject = new JWEObject(jweHeader, new Payload(data));
		jweObject.encrypt(new RSAEncrypter(publicKey));
		return jweObject.serialize();

	}

	/**
	 * Metodo principal que realiza la inicializacion de la variable
	 * llama al metodo para generar firma digital y encriptar informacion
	 * @param data (Informacion a encriptar)
	 * @return
	 */
	public String encript(String data,String uriPrivateKey,String uriPublicKey) throws Exception {
		inicializar();
		PrivateKey privateKey = generateKeyPrivate(uriPrivateKey);
		PublicKey publicKey = generateKeyPublic(uriPublicKey);
		return generateJweJws(data, (RSAPrivateKey) privateKey, (RSAPublicKey) publicKey);

	}

	/**
	 * Metodo principal que ayuda a desencriptar la info compartida por vision +
	 * @param encrypt (Data encriptada que se desea desencriptar)
	 * @return
	 * @throws Exception
	 */
	public String descrypt(String encrypt,String uriPrivateKey,String uriPublicKey) throws Exception {
		inicializar();
		PrivateKey privateKey = generateKeyPrivate(uriPrivateKey);
		PublicKey publicKey = generateKeyPublic(uriPublicKey);
		String jweExtract = verifyExtractJweFromJWS(encrypt,  (RSAPublicKey) publicKey);
		if(jweExtract != null) {
			return  decryptJwe(jweExtract,(RSAPrivateKey) privateKey);
		}
		throw new NullPointerException("No se pudo realizar el desencriptado");

	}

	/**
	 * Creador de header para saber que tipo de encriptado se usa
	 * @param kid
	 * @param jweAlgorithm
	 * @param encriptionMethod
	 * @param additionalHeaders
	 * @return
	 */
	private JWEHeader header(String kid, JWEAlgorithm jweAlgorithm, EncryptionMethod encriptionMethod,
			Map<String, Object> additionalHeaders) {
		JWEHeader.Builder builder = new JWEHeader.Builder(jweAlgorithm, encriptionMethod).keyID(kid)
				.type(JOSEObjectType.JOSE);
		if (additionalHeaders != null && additionalHeaders.size() > 0) {
			for (Map.Entry<String,Object> k : additionalHeaders.entrySet()) {
				Object value = k.getValue();
				String key = k.getKey();
				if (HEADER_CTY.equalsIgnoreCase(key)) {
					builder.contentType(value.toString());
				} else {
					builder.customParam(key, value);
				}
			}
		}
		
		return builder.build();
	}

	/**
	 * Verifica que la informacion que se desea desencriptar se encripta con el certificado publico que
	 * se tiene
	 * @param jws (data encriptada)
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	private String verifyExtractJweFromJWS(String jws, RSAPublicKey publicKey) throws Exception {
		JWSObject jwsObject = JWSObject.parse(jws);
		if (!jwsObject.verify(new RSASSAVerifier(publicKey))) {
		
			return null;
		}
		
		return jwsObject.getPayload().toString();
	}

	
	/**
	 * Extrae la informacion verificando el tipo de algoritmo que se usa para encriptar
	 * @param jweString
	 * @param rsaPrivateKey
	 * @return
	 * @throws Exception
	 */
	private String decryptJwe(String jweString, RSAPrivateKey rsaPrivateKey) throws Exception {
		JWEObject jweObject = JWEObject.parse(jweString);
		JWEHeader header = jweObject.getHeader();
		JWEAlgorithm jweAlgorithm = header.getAlgorithm();
		if (JWEAlgorithm.RSA_OAEP_256.equals(jweAlgorithm)) {
			jweObject.decrypt(new RSADecrypter(rsaPrivateKey));
			
			return jweObject.getPayload().toString();
		} 
		else {
			return null;
		}

	}
	
	
	

}
