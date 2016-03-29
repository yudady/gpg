package com.foya.gpg.ok;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.util.Iterator;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.util.encoders.Hex;

import com.foya.gpg.ok.tool.PGPUtils;

public class PrivateKeyFileInfo {

	public static void main(String[] args) throws Exception {
		//secring.gpg
		//tommy_private.asc

		String privateKeyFileName = "F:/foya/02.tommy4Git/gpg/src/main/resources/secring.gpg";
		FileInputStream privateKeyIn = new FileInputStream(privateKeyFileName);
		PGPSecretKey pgpPrivateKey = PGPUtils.readSecretKey(privateKeyIn);
		System.out.println(ToStringBuilder.reflectionToString(pgpPrivateKey, ToStringStyle.MULTI_LINE_STYLE));
		System.out.println(pgpPrivateKey.getKeyEncryptionAlgorithm() + "   =>  " + PubringDumpKeyInfo.getAlgorithm(pgpPrivateKey.getKeyEncryptionAlgorithm()));
		System.out.println(pgpPrivateKey.getKeyID());
		System.out.println(ToStringBuilder.reflectionToString(pgpPrivateKey.getS2KUsage(), ToStringStyle.MULTI_LINE_STYLE));
		System.out.println(pgpPrivateKey.getS2K());

		Iterator userAttributes = pgpPrivateKey.getUserAttributes();
		while (userAttributes.hasNext()) {

			System.out.println("userAttributes = >" + ToStringBuilder.reflectionToString(userAttributes.next(), ToStringStyle.MULTI_LINE_STYLE));
		}
		int count = 0;
		for (java.util.Iterator iterator = pgpPrivateKey.getUserIDs(); iterator.hasNext();) {
			count++;
			System.out.println((String) iterator.next());
		}
		System.out.println("-------------->Key Count = " + count);
		System.out.println("public start -------");
		PGPPublicKey pgpPublicKey = pgpPrivateKey.getPublicKey();
		System.out.println("Key Strength = " + pgpPublicKey.getBitStrength());
		System.out.println("Algorithm = " + PubringDumpKeyInfo.getAlgorithm(pgpPublicKey.getAlgorithm()));
		System.out.println("Bit strength = " + pgpPublicKey.getBitStrength());
		System.out.println("Version = " + pgpPublicKey.getVersion());
		System.out.println("Encryption key = " + pgpPublicKey.isEncryptionKey() + ", Master key = " + pgpPublicKey.isMasterKey());
		System.out.println("Fingerprint: " + new String(Hex.encode(pgpPublicKey.getFingerprint())));
		System.out.println("public end -------");



// FIXME
//
//
//
//		PGPPrivateKey privateKey = PGPUtils.findPrivateKey(privateKeyIn, pgpPrivateKey.getKeyID(), "tommy".toCharArray());
//		PrivateKey pk = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider()).getPrivateKey(privateKey);
//		System.out.println(privateKey);
	}

}
