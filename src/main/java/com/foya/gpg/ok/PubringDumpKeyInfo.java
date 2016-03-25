package com.foya.gpg.ok;

import java.io.FileInputStream;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;


public class PubringDumpKeyInfo {


	public static String getAlgorithm(int algId) {
		switch (algId) {
			case PublicKeyAlgorithmTags.RSA_GENERAL:
				return "RSA_GENERAL";
			case PublicKeyAlgorithmTags.RSA_ENCRYPT:
				return "RSA_ENCRYPT";
			case PublicKeyAlgorithmTags.RSA_SIGN:
				return "RSA_SIGN";
			case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
				return "ELGAMAL_ENCRYPT";
			case PublicKeyAlgorithmTags.DSA:
				return "DSA";
			case PublicKeyAlgorithmTags.ECDH:
				return "ECDH";
			case PublicKeyAlgorithmTags.ECDSA:
				return "ECDSA";
			case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
				return "ELGAMAL_GENERAL";
			case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
				return "DIFFIE_HELLMAN";
		}

		return "unknown";
	}

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		//String publicKeyPath = "F:/foya/00.work/gpg/src/main/resources/pubring.gpg";
		String publicKeyPath = "F:/foya/00.work/gpg/src/main/resources/dummy.asc";
		//
		// Read the public key rings
		//
		PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(new FileInputStream(publicKeyPath)), new JcaKeyFingerprintCalculator());

		Iterator rIt = pubRings.getKeyRings();

		while (rIt.hasNext()) {
			PGPPublicKeyRing pgpPub = (PGPPublicKeyRing) rIt.next();

			try {
				pgpPub.getPublicKey();
			} catch (Exception e) {
				e.printStackTrace();
				continue;
			}

			Iterator it = pgpPub.getPublicKeys();
			boolean first = true;
			while (it.hasNext()) {
				PGPPublicKey pgpKey = (PGPPublicKey) it.next();

				if (first) {
					first = false;
					System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()));
				} else {
					System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()) + " (subkey)");
				}

				Iterator userIDs = pgpKey.getUserIDs();
				while (userIDs.hasNext()) {
					System.out.println("userIDs: " + userIDs.next());
				}
				Iterator userAttributes = pgpKey.getUserAttributes();
				while (userAttributes.hasNext()) {
					System.out.println("userAttributes: " + userAttributes.next());
				}

				System.out.println("            Algorithm: " + getAlgorithm(pgpKey.getAlgorithm()));
				System.out.println("            Fingerprint: " + new String(Hex.encode(pgpKey.getFingerprint())));
			}
		}
	}
}
