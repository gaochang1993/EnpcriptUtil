package com.unionpay.sm;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyPair;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

public class SM2UtilTest extends TestCase {
	
	public static AsymmetricCipherKeyPair keyPair =SM2Util.generateKeyPair();
	public static ECPoint pubKey;
	public static BigInteger priKey;
	public static String plainText = "中国银联科技事业部个性化团队高畅"; 
	public static String ciphered ="";
	
	public static void getKey(){
		
		SM2 sm2 =new SM2();
		 //AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();        
	     ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keyPair.getPrivate();  
	     ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keyPair.getPublic();  
	     BigInteger privateKey = ecpriv.getD();  
	     ECPoint publicKey = ecpub.getQ();
	}

	public final void  testEncryptByteArrayECPoint() throws UnsupportedEncodingException, IOException {
		getKey();
		ciphered =SM2Util.encrypt(plainText.getBytes("utf-8"), pubKey);
		assertFalse(ciphered.equals(Util.byteToHex(plainText.getBytes("utf-8"))));
		
	}

	public final void testEncryptByteArrayByteArray() throws UnsupportedEncodingException, IOException {
		byte[] pubBytes =pubKey.getEncoded();
		String ciphered =SM2Util.encrypt(plainText.getBytes("utf-8"), pubBytes);
		assertFalse(ciphered.equals(Util.byteToHex(plainText.getBytes("utf-8"))));

	}

	public final void testDecryptByteArrayByteArray() throws IOException {
		byte[] decipher =SM2Util.decrypt(Hex.decode(ciphered), priKey.toByteArray());
		assertTrue(plainText.equals(new String(decipher)));
	}

	public final void testDecryptByteArrayBigInteger() throws IOException {
		byte[] decipher =SM2Util.decrypt(Hex.decode(ciphered), priKey);
		assertTrue(plainText.equals(new String(decipher)));
	}

}
