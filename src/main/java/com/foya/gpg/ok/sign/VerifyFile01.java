package com.foya.gpg.ok.sign;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import me.sniggle.pgp.crypt.MessageEncryptor;
import me.sniggle.pgp.crypt.PGPWrapperFactory;

public class VerifyFile01 {

	private static final Logger mLogger = LoggerFactory.getLogger(VerifyFile01.class);

	public static void verifyFile(InputStream signSourceIn, InputStream publicKeyIn, OutputStream decryptOut) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		InputStream decoderIn = PGPUtil.getDecoderStream(signSourceIn);

		PGPObjectFactory pgpFact = new JcaPGPObjectFactory(decoderIn);

		PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();

		pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

		PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();

		PGPOnePassSignature ops = p1.get(0);

		PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

		InputStream dIn = p2.getInputStream();
		int ch;
		PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyIn), new JcaKeyFingerprintCalculator());

		PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());

		ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider(new BouncyCastleProvider()), key);

		while ((ch = dIn.read()) >= 0) {
			ops.update((byte) ch);
			decryptOut.write(ch);
		}

		decryptOut.close();

		PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

		if (ops.verify(p3.get(0))) {
			System.out.println("signature verified.");
		} else {
			System.out.println("signature verification failed.");
		}
	}

	@Test
	public void verifyAndDecrypt() throws Exception {
		try {
			FileInputStream in = new FileInputStream(new File("e:/tmp/123.encrypt.sign.txt"));
			FileInputStream pKeyIn = new FileInputStream(new File("F:/foya/02.tommy4Git/gpg/src/main/resources/tstar_public.asc"));
			FileOutputStream outVerify = new FileOutputStream(new File("C:/Users/tommy/Desktop/123.verify.sign.txt"));
			verifyFile(in, pKeyIn, outVerify);

			in.close();
			pKeyIn.close();
			outVerify.close();
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	public void decrypt() throws Exception {
		String receiverPassword = "tommy";
		String receiverPriveteKey = "F:/foya/02.tommy4Git/gpg/src/main/resources/tommy_private.asc";
		InputStream privateKeyOfReceiver = null;
		InputStream encryptedData = null;
		OutputStream target = null;

		MessageEncryptor encyptor = PGPWrapperFactory.getEncyptor();
		try {
			String passwordOfReceiversPrivateKey = receiverPassword;
			privateKeyOfReceiver = new FileInputStream(new File(receiverPriveteKey));
			encryptedData = new FileInputStream(new File("C:/Users/tommy/Desktop/123.verify.sign.txt"));
			target = new FileOutputStream(new File("C:/Users/tommy/Desktop/123.verify.decrypt.txt"));
			encyptor.decrypt(passwordOfReceiversPrivateKey, privateKeyOfReceiver, encryptedData, target);
		} finally {
			IOUtils.closeQuietly(privateKeyOfReceiver);
			IOUtils.closeQuietly(encryptedData);
			IOUtils.closeQuietly(target);
		}
	}

}
