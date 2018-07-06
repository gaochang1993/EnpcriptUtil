package com.unionpay.EnpcriptUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.params.KeyParameter;

public class AesUtil {
	
		private static final String CIPHER_ALGORITHM_AES ="AES/CBC/PKCS5Padding";
		
		private static final byte[] IVPARAMETER_DATA = { 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x34,0x30, 0x35, 0x30, 0x36, 0x30, 0x37, 0x30, 0x38};
		
		
		/**
		 * aes加密
		 * @param data
		 * @param key
		 * @throws NoSuchPaddingException 
		 * @throws NoSuchAlgorithmException 
		 * @throws InvalidKeyException 
		 * @throws BadPaddingException 
		 * @throws IllegalBlockSizeException 
		 * @throws InvalidAlgorithmParameterException 
		 */
		public static byte[] encryptAes(byte[] data,SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
			Cipher cipher =Cipher.getInstance(CIPHER_ALGORITHM_AES);
			cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IVPARAMETER_DATA));
			return cipher.doFinal(data);
		}
		
		/**
		 * aes加密
		 * @param data
		 * @param keySpec
		 * @throws NoSuchPaddingException 
		 * @throws NoSuchAlgorithmException 
		 * @throws InvalidKeyException 
		 * @throws BadPaddingException 
		 * @throws IllegalBlockSizeException 
		 * @throws InvalidKeySpecException 
		 * @throws InvalidAlgorithmParameterException 
		 */
		public static byte[] encryptAes(byte[] data,byte[] keySpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
			SecretKey key =KeyUtil.genAesKey(keySpec);
			return encryptAes(data, key);
			
		}
			
		/**
		 * aes 解密
		 * @param cipheredData
		 * @param key
		 * @throws NoSuchPaddingException 
		 * @throws NoSuchAlgorithmException 
		 * @throws InvalidKeyException 
		 * @throws BadPaddingException 
		 * @throws IllegalBlockSizeException 
		 * @throws InvalidAlgorithmParameterException 
		 */
		public static byte[] decryptAes(byte[] cipheredData,SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
			Cipher cipher =Cipher.getInstance(CIPHER_ALGORITHM_AES);
			cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IVPARAMETER_DATA));
			return cipher.doFinal(cipheredData);
		}
		
		/**
		 * aes 解密
		 * @param cipheredData
		 * @param keySpec
		 * @throws NoSuchPaddingException 
		 * @throws NoSuchAlgorithmException 
		 * @throws InvalidKeyException 
		 * @throws BadPaddingException 
		 * @throws IllegalBlockSizeException 
		 * @throws InvalidKeySpecException 
		 * @throws InvalidAlgorithmParameterException 
		 */
		public static byte[] decryptAes(byte[] cipheredData,byte[] keySpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
			SecretKey key=KeyUtil.genAesKey(keySpec);
			return decryptAes(cipheredData, key);
		}
		

}
