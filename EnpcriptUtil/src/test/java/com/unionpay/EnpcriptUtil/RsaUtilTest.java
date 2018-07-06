package com.unionpay.EnpcriptUtil;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import junit.framework.TestCase;

public class RsaUtilTest extends TestCase {
	public static KeyPair KEYPAIR;
	private static String SOURCE ="中国银联科技事业部个性化团队高畅";
	private static byte[] ENCRYPTED_PUBLICKEY =null;
	private static byte[] ENCRYPTED_PRIVATEKEY =null;
	private static byte[] SIGN =null;
	static{
		try {
			KEYPAIR =KeyUtil.genRsaKeyPair(1024, new SecureRandom());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	//test RsaUtil.encryptByPubKey(byte[], RSAPublicKey)
	public final void testEncryptByPubKeyByteArrayRSAPublicKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		RSAPublicKey rsaPublicKey =(RSAPublicKey) KEYPAIR.getPublic();
		byte[] encrypted =RsaUtil.encryptByPubKey(SOURCE.getBytes("utf-8"), rsaPublicKey);
		ENCRYPTED_PUBLICKEY  =encrypted;
		assertFalse(SOURCE.equals(new String(encrypted)));
	}

	//test RsaUtil.encryptByPubKey(byte[], byte[])
	public final void testEncryptByPubKeyByteArrayByteArray() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, UnsupportedEncodingException {
		byte[] keySpec = ((RSAPublicKey) KEYPAIR.getPublic()).getEncoded();
		byte[] encrypted =RsaUtil.encryptByPubKey(SOURCE.getBytes("utf-8"), keySpec);
		assertFalse(SOURCE.equals(new String(encrypted)));
	}
	
	//test RsaUtil.encryptByPriKey(byte[], RSAPrivateKey)
	public final void testEncryptByPriKeyByteArrayRSAPrivateKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, UnsupportedEncodingException {
		RSAPrivateKey rsaPrivateKey =(RSAPrivateKey) KEYPAIR.getPrivate();
		byte[] encrypted =RsaUtil.encryptByPriKey(SOURCE.getBytes("utf-8"), rsaPrivateKey);
		ENCRYPTED_PRIVATEKEY  =encrypted;
		assertFalse(SOURCE.equals(new String(encrypted)));
	}

	//test RsaUtil.encryptByPriKey(byte[], byte[])
	public final void testEncryptByPriKeyByteArrayByteArray() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, UnsupportedEncodingException {
		byte[] rsaPrivateKey =((RSAPrivateKey) KEYPAIR.getPrivate()).getEncoded();
		byte[] encrypted =RsaUtil.encryptByPriKey(SOURCE.getBytes("utf-8"), rsaPrivateKey);
		assertFalse(SOURCE.equals(new String(encrypted)));
	}


	//test RsaUtil.decryptByPubKey(byte[], RSAPublicKey)
	public final void testDecryptByPubKeyByteArrayRSAPublicKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		RSAPublicKey rsaPublicKey =(RSAPublicKey) KEYPAIR.getPublic();
		byte[] decrypted =RsaUtil.decryptByPubKey(ENCRYPTED_PRIVATEKEY, rsaPublicKey);		
		assertTrue(SOURCE.equals(new String(decrypted)));
	}

	//test RsaUtil.decryptByPubKey(byte[], byte[])
	public final void testDecryptByPubKeyByteArrayByteArray() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		byte[] rsaPublicKey =((RSAPublicKey) KEYPAIR.getPublic()).getEncoded();
		byte[] decrypted =RsaUtil.decryptByPubKey(ENCRYPTED_PRIVATEKEY, rsaPublicKey);
		assertTrue(SOURCE.equals(new String(decrypted)));
	}

	//test RsaUtil.decryptByPriKey(byte[], RSAPrivateKey)
	public final void testDecryptByPriKeyByteArrayRSAPrivateKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		RSAPrivateKey rsaPrivateKey =(RSAPrivateKey) KEYPAIR.getPrivate();
		byte[] decrypted =RsaUtil.decryptByPriKey(ENCRYPTED_PUBLICKEY, rsaPrivateKey);
		assertTrue(SOURCE.equals(new String(decrypted)));
	}

	//test RsaUtil.decryptByPriKey(byte[], byte[])
	public final void testDecryptByPriKeyByteArrayByteArray() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		byte[] rsaPrivateKey =((RSAPrivateKey) KEYPAIR.getPrivate()).getEncoded();
		byte[] decrypted =RsaUtil.decryptByPriKey(ENCRYPTED_PUBLICKEY, rsaPrivateKey);
		assertTrue(SOURCE.equals(new String(decrypted)));
	}

	//test RsaUtil.verifyByPubkey(byte[],RSAPublicKey,byte[])
	public final void testVerifyByPubkeyByteArrayRSAPublicKeyByteArray() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException {
		SIGN=RsaUtil.signByPriKey(SOURCE.getBytes("utf-8"), (RSAPrivateKey) KEYPAIR.getPrivate());
		assertTrue(RsaUtil.verifyByPubkey(SOURCE.getBytes("utf-8"),(RSAPublicKey)KEYPAIR.getPublic() , SIGN));
	}

	//test RsaUtil.verifyByPubkey(byte[],byte[],byte[])
	public final void testVerifyByPubkeyByteArrayByteArrayByteArray() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException, InvalidKeySpecException {
		
		assertTrue(RsaUtil.verifyByPubkey(SOURCE.getBytes("utf-8"),((RSAPublicKey)KEYPAIR.getPublic()).getEncoded() , SIGN));
	}

}
