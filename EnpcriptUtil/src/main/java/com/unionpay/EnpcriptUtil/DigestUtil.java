package com.unionpay.EnpcriptUtil;


import org.apache.commons.codec.digest.DigestUtils;

public class DigestUtil {

	/**
	 * md5
	 * @param data
	 * @return hex string
	 */
	public static String encrypByMd5(byte[] data) {
		return DigestUtils.md5Hex(data);
	}
	
	/**
	 * md5
	 * @param data
	 * @return hex string
	 */
	public static String encrypByMd5(String data) {
		return DigestUtils.md5Hex(data);
	}
	
	/**
	 * sha1
	 * @param data
	 * @return hex string
	 */
	public static String encrypBySha1(byte[] data) {
		return DigestUtils.sha1Hex(data);
	}
	
	/**
	 * sha1
	 * @param data
	 * @return hex string
	 */
	public static String encrypBySha1(String data) {
		return DigestUtils.sha1Hex(data);
	}
	
	
	/**
	 * sha256
	 * @return 
	 */
	public static String encrypBySha256(byte[] data) {
		return DigestUtils.sha256Hex(data);
	}
	
	/**
	 * sha256
	 * @return 
	 */
	public static  String encryptBySha256(String data) {
		return DigestUtils.sha256Hex(data);
	}
		
	
}
