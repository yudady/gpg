package com.foya.gpg.ok;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Iterator;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.util.encoders.Hex;

import com.foya.gpg.ok.tool.PGPUtils;

public class PublicKeyFileInfo {

	public static void main(String[] args) throws Exception {
		String[] arr = new String[] { "tommy_public.asc", "tstar_public.asc", "receiverPublicKey", };
		String publicKeyFileName = "F:/foya/02.tommy4Git/gpg/src/main/resources/";
		keyInfo(publicKeyFileName + arr[2]);

	}

	private static void keyInfo(String publicKeyFileName) throws FileNotFoundException, IOException, PGPException {
		FileInputStream publicKeyIn = new FileInputStream(publicKeyFileName);

		PGPPublicKey pgpPublicKey = PGPUtils.readPublicKey(publicKeyIn);
		System.out.println(ToStringBuilder.reflectionToString(pgpPublicKey, ToStringStyle.MULTI_LINE_STYLE));
		System.out.println("-----------");
		System.out.println(ToStringBuilder.reflectionToString(pgpPublicKey.getPublicKeyPacket(), ToStringStyle.MULTI_LINE_STYLE));
		System.out.println("-----------");

		Iterator signatures = pgpPublicKey.getSignatures();
		while (signatures.hasNext()) {
			System.out.println(ToStringBuilder.reflectionToString(signatures.next(), ToStringStyle.MULTI_LINE_STYLE));
		}
		System.out.println("-----------");

		// find out a little about the keys in the public key ring
		System.out.println("Key Strength = " + pgpPublicKey.getBitStrength());
		System.out.println("Algorithm = " + PubringDumpKeyInfo.getAlgorithm(pgpPublicKey.getAlgorithm()));
		System.out.println("Bit strength = " + pgpPublicKey.getBitStrength());
		System.out.println("Version = " + pgpPublicKey.getVersion());
		System.out.println("Encryption key = " + pgpPublicKey.isEncryptionKey() + ", Master key = " + pgpPublicKey.isMasterKey());
		System.out.println("Fingerprint: " + new String(Hex.encode(pgpPublicKey.getFingerprint())));
		int count = 0;
		for (java.util.Iterator iterator = pgpPublicKey.getUserIDs(); iterator.hasNext();) {
			count++;
			System.out.println((String) iterator.next());
		}
		System.out.println("Key Count = " + count);

		System.out.println("---publicKey--------");

		PublicKey publicKey = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider()).getPublicKey(pgpPublicKey);
		System.out.println(publicKey);
	}

}
