package com.foya.gpg.ok.sign;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
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

public class VerifyFile {

	private static final Logger mLogger = LoggerFactory.getLogger(VerifyFile.class);

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

	public static boolean verifyFile(InputStream signSourceIn, InputStream publicKeyIn, String outVerifyFile) throws Exception {
		byte[] signSourceInBytes = VerifyFile.inputStream2BytesLog(signSourceIn);
		System.out.println("[LOG] 1 s-------------");
		Security.addProvider(new BouncyCastleProvider());
		System.out.println("[LOG] 1 e-------------");

		System.out.println("[LOG] 2 s-------------");
		byte[] decoderInBytes = VerifyFile.inputStream2BytesLog(PGPUtil.getDecoderStream(new ByteArrayInputStream(signSourceInBytes)));
		System.out.println("[LOG] 2 e-------------");
		PGPObjectFactory factory = new JcaPGPObjectFactory(new ByteArrayInputStream(decoderInBytes));

		PGPCompressedData pgpCompressedData = (PGPCompressedData) factory.nextObject();
		mLogger.debug("[LOG][pgpCompressedData]" + ToStringBuilder.reflectionToString(pgpCompressedData));
		mLogger.debug("[LOG][pgpCompressedData]" + VerifyFile.getAlgorithm(pgpCompressedData.getAlgorithm()));

		System.out.println("[LOG] 3 s-------------");
		byte[] dataStreamBytes = VerifyFile.inputStream2BytesLog(pgpCompressedData.getDataStream());
		System.out.println("[LOG] 3 e-------------");

		PGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(new ByteArrayInputStream(dataStreamBytes));

		PGPOnePassSignatureList pgpOnePassSignatureList = (PGPOnePassSignatureList) pgpObjectFactory.nextObject();

		PGPOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList.get(0);
		mLogger.debug("[LOG][pgpOnePassSignature]" + ToStringBuilder.reflectionToString(pgpOnePassSignature));
		mLogger.debug("[LOG][pgpOnePassSignature]" + ToStringBuilder.reflectionToString(pgpOnePassSignature.getKeyID()));
		mLogger.debug("[LOG][pgpOnePassSignature]" + ToStringBuilder.reflectionToString(pgpOnePassSignature.getKeyAlgorithm()));
		mLogger.debug("[LOG][pgpOnePassSignature]" + ToStringBuilder.reflectionToString(pgpOnePassSignature.getSignatureType()));
		PGPLiteralData pgpLiteralData = (PGPLiteralData) pgpObjectFactory.nextObject();

		System.out.println("[LOG] 4 s-------------");
		byte[] dInBytes = VerifyFile.inputStream2BytesLog(pgpLiteralData.getInputStream());
		System.out.println("[LOG] 4 e-------------");

		PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyIn), new JcaKeyFingerprintCalculator());

		PGPPublicKey key = pgpRing.getPublicKey(pgpOnePassSignature.getKeyID());

		pgpOnePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider(new BouncyCastleProvider()), key);
		for (int i = 0; i < dInBytes.length; i++) {
			pgpOnePassSignature.update(dInBytes[i]);
		}

		PGPSignatureList pgpSignatureList = (PGPSignatureList) pgpObjectFactory.nextObject();

		if (pgpOnePassSignature.verify(pgpSignatureList.get(0))) {
			mLogger.debug("[LOG]***********[signature verified]***********");
			mLogger.debug("[LOG]***********[signature verified]***********");
			mLogger.debug("[LOG]***********[signature verified]***********");
			mLogger.debug("[LOG]***********[signature verified]***********");
			mLogger.debug("[LOG]***********[signature verified]***********");

			OutputStream decryptOut = new FileOutputStream(new File(outVerifyFile));
			for (int i = 0; i < dInBytes.length; i++) {
				decryptOut.write(dInBytes[i]);
			}
			decryptOut.close();

			return true;
		}
		mLogger.debug("[LOG]***********[signature verification failed]***********");
		return false;
	}

	private static byte[] inputStream2BytesLog(InputStream signSourceIn) throws IOException {
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		IOUtils.copy(signSourceIn, bao);
		byte[] signSourceInBytes = bao.toByteArray();
		String signSourceInString = IOUtils.toString(new ByteArrayInputStream(signSourceInBytes), StandardCharsets.UTF_8.name());
		mLogger.debug(signSourceInString);
		return signSourceInBytes;
	}

	@Test
	public void verifyAndDecrypt() throws Exception {
		try {
			FileInputStream in = new FileInputStream(new File("e:/tmp/123.encrypt.sign.txt"));
			//			FileInputStream in = new FileInputStream(new File("e:/tmp/123.encrypt.sign.error.txt"));
			FileInputStream pKeyIn = new FileInputStream(new File("F:/foya/02.tommy4Git/gpg/src/main/resources/tstar_public.asc"));
			verifyFile(in, pKeyIn, "C:/Users/tommy/Desktop/123.verify.sign.txt");

			in.close();
			pKeyIn.close();
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
