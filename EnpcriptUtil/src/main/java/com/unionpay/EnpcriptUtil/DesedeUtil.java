package com.unionpay.EnpcriptUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class DesedeUtil {
		//CBC方式加密
		private static final String CIPHER_ALGORITHM_CBC ="DESede/CBC/PKCS5Padding";
		//ECB方式加密	
		private static final String CIPHER_ALGORITHM_ECB ="DESede/ECB/PKCS5Padding";
		
		private static final byte[] IVPARAMETER_DATA = { 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x30, 0x34};
		
		/**
		 * cbc加密
		 * @param data
		 * @param key
		 * @throws NoSuchPaddingException 
		 * @throws NoSuchAlgorithmException 
		 * @throws InvalidKeyException 
		 * @throws BadPaddingException 
		 * @throws IllegalBlockSizeException 
		 * @throws InvalidAlgorithmParameterException 
		 */
		public static byte[] encryptCbc(byte[] data,SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
			Cipher cipher =Cipher.getInstance(CIPHER_ALGORITHM_CBC);
			cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IVPARAMETER_DATA));
			return cipher.doFinal(data);
		}
		
		/**
		 * cbc加密
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
		public static byte[] encryptCbc(byte[] data,byte[] keySpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
			SecretKey key =KeyUtil.gen3DesKey(keySpec);
			return encryptCbc(data, key);
		}
		
		/**
		 * ecb加密
		 * @param data
		 * @param key
		 * @throws NoSuchPaddingException 
		 * @throws NoSuchAlgorithmException 
		 * @throws InvalidKeyException 
		 * @throws BadPaddingException 
		 * @throws IllegalBlockSizeException 
		 */
		public static byte[] encryptEcb(byte[] data,SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
			Cipher cipher =Cipher.getInstance(CIPHER_ALGORITHM_ECB);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(data);
		}
		
		/**
		 * ecb加密
		 * @param data
		 * @param keySpec
		 * @throws NoSuchPaddingException 
		 * @throws NoSuchAlgorithmException 
		 * @throws InvalidKeyException 
		 * @throws BadPaddingException 
		 * @throws IllegalBlockSizeException 
		 * @throws InvalidKeySpecException 
		 */
		public static byte[] encryptEcb(byte[] data,byte[] keySpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
			SecretKey key =KeyUtil.gen3DesKey(keySpec);
			return encryptEcb(data, key);
		}
		
		/**
		 * cbc 解密
		 * @param cipheredData
		 * @param key
		 * @throws NoSuchPaddingException 
		 * @throws NoSuchAlgorithmException 
		 * @throws InvalidKeyException 
		 * @throws BadPaddingException 
		 * @throws IllegalBlockSizeException 
		 * @throws InvalidAlgorithmParameterException 
		 */
		public static byte[] decryptCbc(byte[] cipheredData,SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
			Cipher cipher =Cipher.getInstance(CIPHER_ALGORITHM_CBC);
			cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IVPARAMETER_DATA));
			return cipher.doFinal(cipheredData);
		}
		
		/**
		 * cbc 解密
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
		public static byte[] decryptCbc(byte[] cipheredData,byte[] keySpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
			SecretKey key=KeyUtil.gen3DesKey(keySpec);
			return decryptCbc(cipheredData, key);
		}
		
		/**
		 * ecb 解密
		 * @param cipheredData
		 * @param key
		 * @throws NoSuchPaddingException 
		 * @throws NoSuchAlgorithmException 
		 * @throws InvalidKeyException 
		 * @throws BadPaddingException 
		 * @throws IllegalBlockSizeException 
		 */
		public static byte[] decryptEcb(byte[] cipheredData,SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
			Cipher cipher =Cipher.getInstance(CIPHER_ALGORITHM_ECB);
			cipher.init(Cipher.DECRYPT_MODE,key);
			return cipher.doFinal(cipheredData);
		}
		
		/**
		 * ecb 解密
		 * @param cipheredData
		 * @param keySpec
		 * @throws NoSuchPaddingException 
		 * @throws NoSuchAlgorithmException 
		 * @throws InvalidKeyException 
		 * @throws BadPaddingException 
		 * @throws IllegalBlockSizeException 
		 * @throws InvalidKeySpecException 
		 */
		public static byte[] decryptEcb(byte[] cipheredData,byte[] keySpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
			SecretKey key =KeyUtil.gen3DesKey(keySpec);
			return decryptEcb(cipheredData, key);
		}
}
