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

public class VerifyFile02 {

	private static final Logger mLogger = LoggerFactory.getLogger(VerifyFile02.class);

	public static boolean verifyFile(InputStream signSourceIn, InputStream publicKeyIn , String outVerifyFile) throws Exception {
		byte[] signSourceInBytes = VerifyFile02.inputStream2BytesLog(signSourceIn);
		System.out.println("[LOG] 1 s-------------");
		Security.addProvider(new BouncyCastleProvider());
		System.out.println("[LOG] 1 e-------------");


		System.out.println("[LOG] 2 s-------------");
		byte[] decoderInBytes = VerifyFile02.inputStream2BytesLog(PGPUtil.getDecoderStream(new ByteArrayInputStream(signSourceInBytes)));
		System.out.println("[LOG] 2 e-------------");
		PGPObjectFactory pgpFact = new JcaPGPObjectFactory(new ByteArrayInputStream(decoderInBytes));

		PGPCompressedData pgpCompressedData = (PGPCompressedData) pgpFact.nextObject();




		System.out.println("[LOG] 3 s-------------");
		byte[] dataStreamBytes = VerifyFile02.inputStream2BytesLog(pgpCompressedData.getDataStream());
		System.out.println("[LOG] 3 e-------------");

		PGPObjectFactory pgpFact02 = new JcaPGPObjectFactory(new ByteArrayInputStream(dataStreamBytes));

		PGPOnePassSignatureList pgpOnePassSignatureList = (PGPOnePassSignatureList) pgpFact02.nextObject();

		PGPOnePassSignature ops = pgpOnePassSignatureList.get(0);

		PGPLiteralData pgpLiteralData = (PGPLiteralData) pgpFact02.nextObject();



		System.out.println("[LOG] 4 s-------------");
		byte[] dInBytes = VerifyFile02.inputStream2BytesLog(pgpLiteralData.getInputStream());
		System.out.println("[LOG] 4 e-------------");


		PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyIn), new JcaKeyFingerprintCalculator());

		PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());

		ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider(new BouncyCastleProvider()), key);
		//OutputStream decryptOut = new FileOutputStream(new File(outVerifyFile));
		for(int i = 0 ; i < dInBytes.length ; i++){
			ops.update(dInBytes[i]);
			//decryptOut.write(dInBytes[i]);
		}
		//decryptOut.close();




		PGPSignatureList p3 = (PGPSignatureList) pgpFact02.nextObject();

		if (ops.verify(p3.get(0))) {
			mLogger.debug("[LOG]***********[signature verified]***********");
			mLogger.debug("[LOG]***********[signature verified]***********");
			mLogger.debug("[LOG]***********[signature verified]***********");
			mLogger.debug("[LOG]***********[signature verified]***********");
			mLogger.debug("[LOG]***********[signature verified]***********");
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
			verifyFile(in, pKeyIn , "C:/Users/tommy/Desktop/123.verify.sign.txt");

			in.close();
			pKeyIn.close();
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}




}
