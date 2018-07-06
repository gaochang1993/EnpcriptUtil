package com.unionpay.EnpcriptUtil;
 
import java.security.KeyPair;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
 
 
public class EccUtil {
	
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	
	/**
	 * 公钥加密
	 * @param content
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPubKey(byte[] content, ECPublicKey publicKey) throws Exception{
		Cipher cipher = Cipher.getInstance("ECIES", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(content);
	}
	
	/**
	 * 公钥加密
	 * @param content
	 * @param keySpec
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPubKey(byte[] content,byte[] keySpec) throws Exception{
		ECPublicKey publicKey =KeyUtil.genEccPublicKey(keySpec);
		return encryptByPubKey(content, publicKey);
	}
	
	/**
	 * 私钥解密
	 * @param content
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPriKey(byte[] content, ECPrivateKey privateKey) throws Exception{
		Cipher cipher = Cipher.getInstance("ECIES", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(content);
		
	}
	
	/**
	 * 私钥解密
	 * @param content
	 * @param keySpec
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPriKey(byte[] content, byte[] keySpec) throws Exception{
		ECPrivateKey privateKey =(ECPrivateKey) KeyUtil.genEccPrivateKey(keySpec);
		return decryptByPriKey(content, privateKey);
	}
	
	public static void main(String[] args) throws Exception {
		
		String publicKeyStrBase64 ="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF/COhHsWXPDxnhs25goifXpsjpMnxBKmLFSMF1Jfuvl+Zb+GIxAfLNt0GHmbVOigypAKwfG9owBN1VFEf3fNRg==";
		String privateKeyStrBase64 ="MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgkk9UCGh2eRJ45+8r5nkRHewSSpxttbFwCls5RXJcpYGgCgYIKoZIzj0DAQehRANCAAQX8I6EexZc8PGeGzbmCiJ9emyOkyfEEqYsVIwXUl+6+X5lv4YjEB8s23QYeZtU6KDKkArB8b2jAE3VUUR/d81G";
		
		
		
		KeyPair keyPair =KeyUtil.genEccKeyPair(239);
		ECPublicKey ecPublicKey =(ECPublicKey) keyPair.getPublic();
		ECPrivateKey ecPrivateKey =(ECPrivateKey) keyPair.getPrivate();
		
		System.out.println("ECC公钥Base64编码:" + Base64.getEncoder().encodeToString(ecPublicKey.getEncoded()));
		System.out.println("ECC私钥Base64编码:" + Base64.getEncoder().encodeToString(ecPrivateKey.getEncoded()));
		
		byte[] publicEncrypt = encryptByPubKey("hello world".getBytes(), ecPublicKey);
		byte[] privateDecrypt = decryptByPriKey(publicEncrypt, ecPrivateKey);
		System.out.println(new String(privateDecrypt));
	}
}
