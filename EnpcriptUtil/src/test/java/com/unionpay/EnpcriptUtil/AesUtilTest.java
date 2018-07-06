package com.unionpay.EnpcriptUtil;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import junit.framework.TestCase;

public class AesUtilTest extends TestCase {
	
	private static String source ="中国银联科技事业部个性化团队高畅";
	//private static String base64Source =Base64.getEncoder().encodeToString(source.getBytes());
	private static String key ="19491001";
	
	public static byte[] cipereddata;
	
	//test AesUtil.encryptAes(byte[] ,SecretKey)
	public void testEncryptAesByteArraySecretKey() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
		SecretKey secretKey =KeyUtil.genAesKey(key.getBytes());
		byte[] cipherByte =AesUtil.encryptAes(source.getBytes("utf-8"), secretKey);
		assertFalse(cipherByte.equals(source.getBytes("utf-8")));
	}
	
	//test AesUtil.encryptAes(byte[] ,SecretKeySpec)
	public void testEncryptAesByteArrayByteArray() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, InvalidKeySpecException {
		//SecretKey secretKey =KeyUtil.genAesKey(key.getBytes());
		byte[] cipherByte =AesUtil.encryptAes(source.getBytes("utf-8"), key.getBytes("utf-8"));
		assertFalse(cipherByte.equals(source.getBytes("utf-8")));
	}
	
	//test AesUtil.decryptAes(byte[] ,SecretKey)
	public void testDecryptAesByteArraySecretKey() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
		SecretKey secretKey =KeyUtil.genAesKey(key.getBytes("utf-8"));
		byte[] cipherByte =AesUtil.encryptAes(source.getBytes("utf-8"), secretKey);
		//assertFalse(cipherByte.equals(source.getBytes("utf-8")));
		SecretKey secretKey2 =KeyUtil.genAesKey(key.getBytes("utf-8"));
		byte[] decriptByte =AesUtil.decryptAes(cipherByte, secretKey2);
		assertTrue(source.equals(new String(decriptByte)));
	}
	
	//test AesUtil.encryptAes(byte[] ,SecretKeySpec)
	public void testDecryptAesByteArrayByteArray() throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
		
		byte[] cipherByte =AesUtil.encryptAes(source.getBytes("utf-8"), key.getBytes("utf-8"));
		byte[] decriptByte =AesUtil.decryptAes(cipherByte, key.getBytes("utf-8"));
		assertTrue(source.equals(new String(decriptByte)));
	}

}
