package com.unionpay.sm;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class SM2Util {
	  //生成随机秘钥对 
    public static AsymmetricCipherKeyPair generateKeyPair(){  
        SM2 sm2 = new SM2();
        return sm2.ecc_key_pair_generator.generateKeyPair();  
    }  
      
    /**
     * 数据加密
     * @param data
     * @param publicKey
     * @return
     * @throws IOException
     */
    public static String encrypt(byte[] data ,ECPoint publicKey) throws IOException  
    {  
                
        byte[] source = new byte[data.length];  
        System.arraycopy(data, 0, source, 0, data.length);  
          
        SM2Cipher cipher = new SM2Cipher();  
        SM2 sm2 = new SM2();  
                  
        ECPoint c1 = cipher.Init_enc(sm2, publicKey);  
        cipher.Encrypt(source);  
        byte[] c3 = new byte[32];  
        cipher.Dofinal(c3);  
          
//      System.out.println("C1 " + Util.byteToHex(c1.getEncoded()));  
//      System.out.println("C2 " + Util.byteToHex(source));  
//      System.out.println("C3 " + Util.byteToHex(c3));  
        //C1 C2 C3拼装成加密字串  
        return Util.byteToHex(c1.getEncoded()) + Util.byteToHex(source) + Util.byteToHex(c3);          
    }  
    
    public static String encrypt(byte[] data ,byte[] publicKey) throws IOException{ 
         
    	SM2 sm2 = new SM2();
    	ECPoint pubEcpoint =sm2.ecc_curve.decodePoint(publicKey);
    	return encrypt(data, pubEcpoint);
    }
      
    /**
     * 私钥解密
     * @param privateKey
     * @param encryptedData
     * @return
     * @throws IOException
     */
    public static byte[] decrypt( byte[] encryptedData,byte[] privateKey) throws IOException  
    {  
        BigInteger userD = new BigInteger(1, privateKey);
        return decrypt(encryptedData, userD);
    }  
    public static byte[] decrypt( byte[] encryptedData,BigInteger privateKey) throws IOException  
    {  
        //加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2  
        String data = Util.byteToHex(encryptedData);  
        /***分解加密字串 
         * （C1 = C1标志位2位 + C1实体部分128位 = 130） 
         * （C3 = C3实体部分64位  = 64） 
         * （C2 = encryptedData.length * 2 - C1长度  - C2长度） 
         */  
        byte[] c1Bytes = Util.hexToByte(data.substring(0,130));  
        int c2Len = encryptedData.length - 97;  
        byte[] c2 = Util.hexToByte(data.substring(130,130 + 2 * c2Len));  
        byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len,194 + 2 * c2Len));  
          
        SM2 sm2 = new SM2();
        //igInteger userD = new BigInteger(1, privateKey);  
        //BigInteger userD =privateKey;
        //通过C1实体字节来生成ECPoint  
        ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);  
        SM2Cipher cipher = new SM2Cipher();  
        cipher.Init_dec(privateKey, c1);  
        cipher.Decrypt(c2);  
        cipher.Dofinal(c3);  
          
        //返回解密结果  
        return c2;  
    }  
      
    public static void main(String[] args) throws Exception   
    {  
        //生成密钥对  
        //generateKeyPair();  
          
        String plainText = "中国银联科技事业部个性化团队高畅";  
        byte[] sourceData = plainText.getBytes();  
          
        //下面的秘钥可以使用generateKeyPair()生成的秘钥内容  
        // 国密规范正式私钥  
       // String prik = "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";  
        // 国密规范正式公钥  
        //String pubk = "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";  
        
        SM2 sm2 =new SM2();
        AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();        
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();  
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();  
        BigInteger privateKey = ecpriv.getD();  
        ECPoint publicKey = ecpub.getQ();
        
        System.out.println("加密: ");  
        String cipherText = SM2Util.encrypt(sourceData , publicKey);  
        System.out.println(cipherText);  
        System.out.println("解密: ");  
        String de = new String(SM2Util.decrypt(Hex.decode(cipherText),privateKey.toByteArray()));  
        System.out.println(de);  
          
    }  


}
