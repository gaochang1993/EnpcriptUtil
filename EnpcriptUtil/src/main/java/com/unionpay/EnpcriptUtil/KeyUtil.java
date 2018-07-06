package com.unionpay.EnpcriptUtil;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

public class KeyUtil {
	
	
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	/**
	 * 生成des密钥
	 * @param keySpec
	 * @return 
	 * @throws InvalidKeyException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static SecretKey genDesKey(byte[] keySpec) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
		DESKeySpec desKeySpec =new DESKeySpec(keySpec);
		SecretKeyFactory secretKeyFactory =SecretKeyFactory.getInstance("DES");
		return secretKeyFactory.generateSecret(desKeySpec);
	}
	
	/**
	 * 生成3des密钥
	 * @param keySpec
	 * @return
	 * @throws InvalidKeyException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static SecretKey gen3DesKey(byte[] keySpec) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
	
	 	DESedeKeySpec deSedeKeySpec =new DESedeKeySpec(keySpec);
		SecretKeyFactory secretKeyFactory =SecretKeyFactory.getInstance("DESede");
		return secretKeyFactory.generateSecret(deSedeKeySpec);
		
	
	
	}
	
	/**
	 * 生成aes密钥
	 * @param keySpec
	 * @return
	 * @throws NoSuchAlgorithmException 
	 */
	public static SecretKey genAesKey(byte[] keySpec) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator =KeyGenerator.getInstance("AES");
		keyGenerator.init(new SecureRandom(keySpec));
		return keyGenerator.generateKey();	
		
	}
	
	/**
	 * 获取rsa密钥对
	 * @param keySize
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * 
	 */
	public static KeyPair genRsaKeyPair(int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator keyPair =KeyPairGenerator.getInstance("RSA");
		keyPair.initialize(keySize);
		return keyPair.generateKeyPair();
	}
	
	/**
	 * 获取rsa密钥对
	 * @param keySize
	 * @param random
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * 
	 */
	public static KeyPair genRsaKeyPair(int keySize,SecureRandom random) throws NoSuchAlgorithmException {
		KeyPairGenerator keyPair =KeyPairGenerator.getInstance("RSA");
		keyPair.initialize(keySize,random);
		return keyPair.generateKeyPair();
	}
	
	/**
	 * 获取rsa 私钥
	 * @param keySpec 
	 * @return NoSuchAlgorithmException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * 
	 */	
	public static PrivateKey genPrivateKey(byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(key);
        return keyFactory.generatePrivate(privateKeySpec);
	}
	
	/**
	 * 获取rsa 公钥
	 * @param keySpec 
	 * @return NoSuchAlgorithmException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * 
	 */	
	public static PublicKey genPublicKey(byte[] keySpec) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keySpec);
        return keyFactory.generatePublic(publicKeySpec);
	}
	
	/**
	 * 获取ecc密钥对
	 * @param keySize
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws NoSuchProviderException 
	 * 
	 */
	public static KeyPair genEccKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
		return genEccKeyPair(keySize, new SecureRandom());
	}
	
	/**
	 * 获取ecc密钥对
	 * @param keySize
	 * @param random
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws NoSuchProviderException 
	 * 
	 */
	public static KeyPair genEccKeyPair(int keySize,SecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGeneratorSpi keyPairGeneratorSpi =(KeyPairGeneratorSpi) KeyPairGeneratorSpi.getInstance("EC", "BC");
		keyPairGeneratorSpi.initialize(keySize, random);
		return keyPairGeneratorSpi.generateKeyPair();
	}
	
	/**
	 * 获取ecc公钥
	 * @param keyPair
	 * @return
	 */
	public static ECPublicKey getPublicKey(KeyPair keyPair){
		return (ECPublicKey) keyPair.getPublic();
		
	}
	
	/**
	 * 获取ecc私钥
	 * @param keyPair
	 * @return
	 */
	public static ECPrivateKey getPrivateKey(KeyPair keyPair){
		return (ECPrivateKey) keyPair.getPrivate();
		
	}
	
	/**
	 * 生成ecc公钥
	 * @param keyBytes
	 * @return
	 * @throws Exception
	 */
	public static ECPublicKey genEccPublicKey(byte[] keyBytes) throws Exception{
		//byte[] keyBytes = AESUtil.base642Byte(pubStr);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
		return (ECPublicKey) keyFactory.generatePublic(keySpec);
		
	}
	
	/**
	 * 生成ecc私钥
	 * @param keyBytes
	 * @return
	 * @throws Exception
	 */
	public static ECPrivateKey genEccPrivateKey(byte[] keyBytes) throws Exception{
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
		return (ECPrivateKey) keyFactory.generatePrivate(keySpec);		
	}
	
	
	public static KeyPair genDsaKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        org.bouncycastle.jcajce.provider.asymmetric.dsa.KeyPairGeneratorSpi keyPairGeneratorSpi = (org.bouncycastle.jcajce.provider.asymmetric.dsa.KeyPairGeneratorSpi) KeyPairGeneratorSpi.getInstance("DSA", "BC");
		keyPairGeneratorSpi.initialize(keySize, new SecureRandom());
		return keyPairGeneratorSpi.generateKeyPair();
	}
	
	
	/**
	 * 生成dsa公钥
	 * @param keyBytes
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static DSAPublicKey genDsaPublicKey(byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory =KeyFactory.getInstance("DSA");
		return (DSAPublicKey) keyFactory.generatePublic(keySpec);
	}
	
	public static DSAPrivateKey denDsaPrivateKey(byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory =KeyFactory.getInstance("DSA");
		return (DSAPrivateKey) keyFactory.generatePrivate(keySpec);
	}
	
	/**
	 * 从pfx文件中读取私钥
	 * @param pfxPath
	 * @param pwd
	 * @return
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws UnrecoverableKeyException 
	 * 
	 */
	public static PrivateKey loadPrivateKeyFromPfx(String pfxPath, String pwd) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(KeyUtil.class.getClassLoader().getResourceAsStream(pfxPath), pwd.toCharArray());
        Enumeration<String> aliasEnum = keyStore.aliases();
        String keyAlias = null;
        if (aliasEnum.hasMoreElements()) {
            keyAlias = aliasEnum.nextElement();
        }
        return (PrivateKey) keyStore.getKey(keyAlias, pwd.toCharArray());
    }
	
	/**
     * 从cer格式的文件中加载公钥
     * @param cerPath
     * @return
     * @throws CertificateException
     * 
     */
    public static PublicKey loadPublicKeyFromCer(String cerPath) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                KeyUtil.class.getClassLoader().getResourceAsStream(cerPath)
        );
        return cert.getPublicKey();
    }
}
