package com.unionpay.EnpcriptUtil;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Hex;

public class RsaUtil {

	private static final String CIPHER_ALGORITHM ="RSA";
	private static final String SIGNATURE_ALGORITHM ="MD5withRSA";
	
	/**
	 * 公钥加密
	 * @param data
	 * @param key
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static byte[] encryptByPubKey(byte[] data,RSAPublicKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher =Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}
	
	/**
	 * 公钥加密
	 * @param data
	 * @param keySpec
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeySpecException 
	 */
	public static byte[] encryptByPubKey(byte[] data,byte[] keySpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		RSAPublicKey rsaPublicKey =(RSAPublicKey) KeyUtil.genPublicKey(keySpec);
		return encryptByPubKey(data, rsaPublicKey);
	}
	
	/**
	 * 公钥解密
	 * @param cipheredData
	 * @param key
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static byte[] decryptByPubKey(byte[] cipheredData,RSAPublicKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher =Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(cipheredData);
	}
	
	/**
	 * 公钥解密
	 * @param cipheredData
	 * @param keySpec
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeySpecException 
	 */
	public static byte[] decryptByPubKey(byte[] cipheredData,byte[] keySpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		RSAPublicKey rsaPublicKey =(RSAPublicKey) KeyUtil.genPublicKey(keySpec);
		return decryptByPubKey(cipheredData, rsaPublicKey);
	}
	
	/**
	 * 私钥加密
	 * @param data
	 * @param key
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static byte[] encryptByPriKey(byte[] data,RSAPrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		Cipher cipher =Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}
	
	/**
	 * 私钥加密
	 * @param data
	 * @param keySpec
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeySpecException 
	 */
	public static byte[] encryptByPriKey(byte[] data,byte[] keySpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		RSAPrivateKey rsaPrivateKey =(RSAPrivateKey) KeyUtil.genPrivateKey(keySpec);
		return encryptByPriKey(data, rsaPrivateKey);
	}
	
	
	/**
	 * 私钥解密
	 * @param cipheredData
	 * @param key
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	public static byte[] decryptByPriKey(byte[] cipheredData,RSAPrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		Cipher cipher =Cipher.getInstance(CIPHER_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(cipheredData);
	}
	
	/**
	 * 私钥解密
	 * @param cipheredData
	 * @param keySpec
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeySpecException 
	 */
	public static byte[] decryptByPriKey(byte[] cipheredData,byte[] keySpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		RSAPrivateKey rsaPrivateKey =(RSAPrivateKey) KeyUtil.genPrivateKey(keySpec);
		return decryptByPriKey(cipheredData, rsaPrivateKey);
	}
	
	/**
	 * 私钥签名
	 * @param data
	 * @param key
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public static byte[] signByPriKey(byte[] data,RSAPrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		Signature signature =Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(key);
		signature.update(data);
		return signature.sign();
	}
	
	/**
	 * 
	 * @param data
	 * @param keySpec
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws InvalidKeySpecException
	 */
	public static byte[] signByPriKey(byte[] data,byte[] keySpec) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException{
		
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) KeyUtil.genPrivateKey(keySpec);
		return signByPriKey(data, rsaPrivateKey);
	}
		
	/**
	 * 公钥验签
	 * @param data
	 * @param publickey
	 * @param sign
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public static boolean verifyByPubkey(byte[] data,RSAPublicKey publicKey,byte[] sign) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature =Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(sign);
	}
	
	/**
	 * 
	 * @param data
	 * @param keySpec
	 * @param sign
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws InvalidKeySpecException
	 */
	public static boolean verifyByPubkey(byte[] data,byte[] keySpec,byte[] sign) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {
		RSAPublicKey publicKey =(RSAPublicKey) KeyUtil.genPublicKey(keySpec);
		return verifyByPubkey(data,publicKey,sign);
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException, SignatureException {
		
		String source ="中国银联科技事业部个性化团队高畅";
        //String key ="194910011949100119491001";
		
		System.out.println(Hex.encodeHex(source.getBytes("utf-8")));
		KeyPair keyPair =KeyUtil.genRsaKeyPair(1024, new SecureRandom());
		byte[] ciphered =encryptByPubKey(source.getBytes("utf-8"), ((RSAPublicKey)keyPair.getPublic()).getEncoded());
		System.out.println(Hex.encodeHex(ciphered));
		byte[] deciphered =decryptByPriKey(ciphered, (RSAPrivateKey) keyPair.getPrivate());
		System.out.println(new String(deciphered));
		
		byte[] sign =signByPriKey(source.getBytes("utf-8"), (RSAPrivateKey) keyPair.getPrivate());
		System.out.println(verifyByPubkey(source.getBytes("utf-8"),(RSAPublicKey)keyPair.getPublic() , sign));
        
	}
	
	
	
	
}
