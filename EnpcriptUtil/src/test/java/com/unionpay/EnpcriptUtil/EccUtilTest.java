package com.unionpay.EnpcriptUtil;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
//import java.security.interfaces.ECPublicKey;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import junit.framework.TestCase;

public class EccUtilTest extends TestCase {
	
	public static KeyPair KEYPAIR;
	private static String SOURCE ="中国银联科技事业部个性化团队高畅";
	private static byte[] ENCRYPTED_PUBLICKEY =null;
	private static byte[] ENCRYPTED_PRIVATEKEY =null;
	static{
		try {
			KEYPAIR =KeyUtil.genEccKeyPair(239, new SecureRandom());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	//test EccUtil.encryptByPubKey(byte[], ECPublicKey)
	public final void testEncryptByPubKeyByteArrayECPublicKey() throws UnsupportedEncodingException, Exception {
		ECPublicKey ecPublicKey =(ECPublicKey) KEYPAIR.getPublic();
		byte[] encrypted =EccUtil.encryptByPubKey(SOURCE.getBytes("utf-8"), ecPublicKey);
		ENCRYPTED_PUBLICKEY =encrypted;
		assertFalse(SOURCE.equals(new String(encrypted)));
	}

	//test EccUtil.encryptByPubKey(byte[], byte[])
	public final void testEncryptByPubKeyByteArrayByteArray() throws UnsupportedEncodingException, Exception {
		byte[] ecPublicKey =((ECPublicKey) KEYPAIR.getPublic()).getEncoded();
		byte[] encrypted =EccUtil.encryptByPubKey(SOURCE.getBytes("utf-8"), ecPublicKey);
		assertFalse(SOURCE.equals(new String(encrypted)));
	}

	//test EccUtil.decryptByPubKey(byte[], ECPrivateKey)
	public final void testDecryptByPriKeyByteArrayECPrivateKey() throws Exception {
		ECPrivateKey ecPrivateKey =(ECPrivateKey) KEYPAIR.getPrivate();
		byte[] decrypted =EccUtil.decryptByPriKey(ENCRYPTED_PUBLICKEY, ecPrivateKey);
		assertTrue(SOURCE.equals(new String(decrypted)));
	}

	//test EccUtil.decryptByPubKey(byte[], byte[])
	public final void testDecryptByPriKeyByteArrayByteArray() throws Exception {
		byte[] ecPrivateKey =((ECPrivateKey) KEYPAIR.getPrivate()).getEncoded();
		byte[] decrypted =EccUtil.decryptByPriKey(ENCRYPTED_PUBLICKEY, ecPrivateKey);
		assertTrue(SOURCE.equals(new String(decrypted)));
	}

}
