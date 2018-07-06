package com.unionpay.EnpcriptUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import junit.framework.TestCase;

public class DesedeUtilTest extends TestCase {
	
	private static String source ="中国银联科技事业部个性化团队高畅";
	
	private static String key ="194910011949100119491001";
	
	//test DesedeUtil.encryptCbc(byte[], secretKey)
	public final void testEncryptCbcByteArraySecretKey() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		SecretKey secretKey =KeyUtil.gen3DesKey(key.getBytes());
		byte[] encriptByte =DesedeUtil.encryptCbc(source.getBytes(), secretKey);
		assertFalse(source.equals(new String(encriptByte)));
	}

	//test DesedeUtil.encryptCbc(byte[], byte[])
	public final void testEncryptCbcByteArrayByteArray() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		//SecretKey secretKey =KeyUtil.gen3DesKey(key.getBytes());
		byte[] encriptByte =DesedeUtil.encryptCbc(source.getBytes(), key.getBytes());
		assertFalse(source.equals(new String(encriptByte)));
	}

	//test DesedeUtil.encryptEcb(byte[], secretKey)
	public final void testEncryptEcbByteArraySecretKey() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		SecretKey secretKey =KeyUtil.gen3DesKey(key.getBytes());
		byte[] encriptByte =DesedeUtil.encryptEcb(source.getBytes(), secretKey);
		assertFalse(source.equals(new String(encriptByte)));
		
	}

	//test DesedeUtil.encryptEcb(byte[], byte[])
	public final void testEncryptEcbByteArrayByteArray() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		SecretKey secretKey =KeyUtil.gen3DesKey(key.getBytes());
		byte[] encriptByte =DesedeUtil.encryptEcb(source.getBytes(), key.getBytes());
		assertFalse(source.equals(new String(encriptByte)));
	}

	//test DesedeUtil.decryptCbc(byte[], secretKey)
	public final void testDecryptCbcByteArraySecretKey() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		SecretKey encryptKey =KeyUtil.gen3DesKey(key.getBytes());
		byte[] encriptByte =DesedeUtil.encryptCbc(source.getBytes(), key.getBytes());
		byte[] decriptByte =DesedeUtil.decryptCbc(encriptByte, encryptKey);
		assertTrue(source.equals(new String(decriptByte)));
		
	}

	//test DesedeUtil.decryptCbc(byte[], byte[])
	public final void testDecryptCbcByteArrayByteArray() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		//SecretKey encryptKey =KeyUtil.gen3DesKey(key.getBytes());
		byte[] encriptByte =DesedeUtil.encryptCbc(source.getBytes(), key.getBytes());
		byte[] decriptByte =DesedeUtil.decryptCbc(encriptByte, key.getBytes());
		assertTrue(source.equals(new String(decriptByte)));
	}

	//test DesedeUtil.decryptEcb(byte[], secretKey)
	public final void testDecryptEcbByteArraySecretKey() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		SecretKey encryptKey =KeyUtil.gen3DesKey(key.getBytes());
		byte[] encriptByte =DesedeUtil.encryptEcb(source.getBytes(), key.getBytes());
		byte[] decriptByte =DesedeUtil.decryptEcb(encriptByte, encryptKey);
		assertTrue(source.equals(new String(decriptByte)));
		
	}

	//test DesedeUtil.decryptEcb(byte[], byte[])
	public final void testDecryptEcbByteArrayByteArray() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		byte[] encriptByte =DesedeUtil.encryptEcb(source.getBytes(), key.getBytes());
		byte[] decriptByte =DesedeUtil.decryptEcb(encriptByte, key.getBytes());
		assertTrue(source.equals(new String(decriptByte)));
	}

}
