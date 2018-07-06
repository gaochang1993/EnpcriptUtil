package com.unionpay.EnpcriptUtil;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import junit.framework.TestCase;

public class DsaUtilTest extends TestCase {
	
	static String source ="中国银联科技事业部个性化团队";
	static String source1 ="中国银联科技事业部个性化团队";
	static KeyPair keyPair;
	static byte[] SIGN =null;
	static String pubByte ="MIIBtzCCASsGByqGSM44BAEwggEeAoGBAOIqsRVgVRdBNz5ShzeVPHBh2l8MwBS4KGVMDt7xZZOKsPjyF+4FUNXSB/qLO5wGSW4kcZT75ITcLE7UE2dz+Xje/p3Hza4ik7JBuZURWpAJZPjP0ny9Vrm7pT1yyfbAxmGcifb8qXXXc3sNpsXic0a2nWyD65jmQlYoZibXBNLvAhUA3zspBrgwHDUnmu+akg0kxBZuSscCgYAu1ql7oMCsH5kcvdUaTdV4Zlm5SSj5QXqyZncNd8W2g7h4jRMxX2y7X285LHdjTpFui2Q2uhlplbygW3h3aKF1ubAjF6QqfEzFMjsZMVU/zk6s28xV1FoI9ibajXo1C5LzRBZHI7p7W9ycwHOQkBiBOOmFUJ/VSM+aXF5zgZV95gOBhQACgYEA2AvBn32Mn9tuxnjCzB8zsZfuXwxhcnQrLcVnGEGU+GOvVKixBum+xGDQDd6KMTwHPQL+EBfBBJDgvT63Gdpq6L/+IvWdET2H1bLD5GsftYaZqwHGRcWc+ivqnbYWJaHIe1Z4i4BzPr/XM9R4IpF67+7wwTE+vbQrSibj04C0pkE=";
	static{
		try {
			keyPair =KeyUtil.genDsaKeyPair(1024);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	 
	static DSAPublicKey dsaPublicKey =(DSAPublicKey) keyPair.getPublic();
	static DSAPrivateKey dsaPrivateKey =(DSAPrivateKey) keyPair.getPrivate();
	static {
		try {
			SIGN =DsaUtil.signByPriKey(source.getBytes("utf-8"), dsaPrivateKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	//test DsaUtil.verifyByPubKey(byte[], DSAPublicKey, byte[])
	public final void testVerifyByPubKeyByteArrayDSAPublicKeyByteArray() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException {
		assertTrue(DsaUtil.verifyByPubKey(source.getBytes("utf-8"), dsaPublicKey, SIGN));
	}

	//test DsaUtil.verifyByPubKey(byte[], byte[], byte[])
	public final void testVerifyByPubKeyByteArrayByteArrayByteArray() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, UnsupportedEncodingException, InvalidKeySpecException {
		assertFalse(DsaUtil.verifyByPubKey(source.getBytes("utf-8"), KeyUtil.genDsaPublicKey(Base64.getDecoder().decode(pubByte)), SIGN));
	}

}
