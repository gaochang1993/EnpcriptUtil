package com.unionpay.sm;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class SM2 {
	
	public final BigInteger ecc_p =new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
	public final BigInteger ecc_a =new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
	public final BigInteger ecc_b =new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
	public final BigInteger ecc_n =new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
	public final BigInteger ecc_gx =new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
	public final BigInteger ecc_gy =new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
	public final ECCurve ecc_curve;
	public final ECPoint ecc_eccPoint_g;	
	public final ECDomainParameters ecc_bc_spec;
	public final ECKeyPairGenerator ecc_key_pair_generator;
	public final ECFieldElement ecc_gx_fieldelement;
	public final ECFieldElement ecc_gy_fieldelement;
	
	
	@SuppressWarnings("deprecation")
	public SM2() {
		// TODO Auto-generated constructor stub
		this.ecc_gx_fieldelement =new ECFieldElement.Fp(this.ecc_p,ecc_gx);
		this.ecc_gy_fieldelement =new ECFieldElement.Fp(this.ecc_p,ecc_gy);
		this.ecc_curve =new ECCurve.Fp(ecc_p, ecc_a, ecc_b);
		this.ecc_eccPoint_g =new ECPoint.Fp(ecc_curve, ecc_gx_fieldelement, ecc_gy_fieldelement);
		this.ecc_bc_spec =new ECDomainParameters(ecc_curve, ecc_eccPoint_g, ecc_n);
		this.ecc_key_pair_generator =new ECKeyPairGenerator();
		ECKeyGenerationParameters ecKeyGenerationParameters =new ECKeyGenerationParameters(ecc_bc_spec, new SecureRandom());
		this.ecc_key_pair_generator.init(ecKeyGenerationParameters);
	}
	
}
