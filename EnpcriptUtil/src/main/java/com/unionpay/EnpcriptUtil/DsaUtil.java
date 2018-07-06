package com.unionpay.EnpcriptUtil;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;

public class DsaUtil {
	
	/**
	 * 私钥数字签名
	 * @param data
	 * @param dsaPrivateKey
	 * @return
	 * 
	 */
	public static byte[] signByPriKey(byte[] data,DSAPrivateKey dsaPrivateKey) throws InvalidKeyException  {
		DSAPrivateKeyParameters dsaPrivateKeyParameters = (DSAPrivateKeyParameters) DSAUtil.generatePrivateKeyParameter(dsaPrivateKey);
	    return signByPriKey(data, dsaPrivateKeyParameters);
	}
	
	/**
	 * 私钥数字签名
	 * @param data
	 * @param dsaPrivateKeyParameters
	 * @return
	 */
	public static byte[] signByPriKey(byte[] data ,DSAPrivateKeyParameters dsaPrivateKeyParameters) {
		DSADigestSigner dsaDigestSigner =new DSADigestSigner(new org.bouncycastle.crypto.signers.DSASigner(),DigestFactory.createMD5());
		dsaDigestSigner.init(true, dsaPrivateKeyParameters);
		dsaDigestSigner.update(data, 0, data.length);
		return dsaDigestSigner.generateSignature();		
	}
	
	/**
	 * 私钥数字签名
	 * @param data
	 * @param priKeyBytes
	 * @param sign
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static byte[] signByPriKey(byte[] data ,byte[] priKeyBytes ,byte[] sign) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
		DSAPrivateKey dsaPrivateKey =KeyUtil.denDsaPrivateKey(priKeyBytes);
		return signByPriKey(data, dsaPrivateKey);
	}
	
	/**
	 * 公钥验签
	 * @param data
	 * @param dsaPublicKey
	 * @param sign
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public static boolean verifyByPubKey(byte[] data,DSAPublicKey dsaPublicKey,byte[] sign) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
		DSAPublicKeyParameters dsaPublicKeyParameters =(DSAPublicKeyParameters) DSAUtil.generatePublicKeyParameter(dsaPublicKey);
		return verifyByPubKey(data, dsaPublicKeyParameters, sign);
		
	}
	
	/**
	 * 公钥验签
	 * @param data
	 * @param dsaPublicKeyParameters
	 * @param sign
	 * @return
	 */
	public static boolean verifyByPubKey(byte[] data,DSAPublicKeyParameters dsaPublicKeyParameters,byte[] sign) {
		
		DSADigestSigner digestSigner =new DSADigestSigner(new org.bouncycastle.crypto.signers.DSASigner(), DigestFactory.createMD5());
		digestSigner.init(false, dsaPublicKeyParameters);
		digestSigner.update(data, 0, data.length);
		return digestSigner.verifySignature(sign);
	}	
	
	/**
	 * 公钥验签
	 * @param data
	 * @param pubKeyBytes
	 * @param sign
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws SignatureException
	 */
	public static boolean verifyByPubKey(byte[] data ,byte[] pubKeyBytes ,byte[] sign) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException, SignatureException {
		DSAPublicKey dsaPublicKey =KeyUtil.genDsaPublicKey(pubKeyBytes);
		return verifyByPubKey(data, dsaPublicKey, sign);
	}
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchProviderException, SignatureException, InvalidKeySpecException {
		
		
		
	}
	
	
	
	
	
	

}
