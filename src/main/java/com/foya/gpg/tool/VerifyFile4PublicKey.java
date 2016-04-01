package com.foya.gpg.tool;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Security;
import java.util.Iterator;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.foya.gpg.ok.tool.PGPUtils;
import com.foya.gpg.tool.algorithm.FoyaAlgorithm;

public class VerifyFile4PublicKey {

	private static final Logger mLogger = LoggerFactory.getLogger(VerifyFile4PublicKey.class);

	public boolean verifyFile(InputStream signSourceIn, InputStream publicKeyIn, String outVerifyFile) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		mLogger.debug("[LOG] 1 s-------------");
		byte[] signSourceInBytes = this.inputStream2BytesLog(signSourceIn);
		mLogger.debug("[LOG] 1 e-------------");

		mLogger.debug("[LOG] 2 s-------------");
		// 把編碼除去 base64 or ascii
		byte[] decoderInBytes = this.inputStream2BytesLog(PGPUtil.getDecoderStream(new ByteArrayInputStream(signSourceInBytes)));
		mLogger.debug("[LOG] 2 e-------------");
		// 轉換成工廠
		JcaPGPObjectFactory unZipfactory = new JcaPGPObjectFactory(decoderInBytes);

		PGPCompressedData pgpCompressedData = (PGPCompressedData) unZipfactory.nextObject();

		mLogger.debug("[LOG][pgpCompressedData]" + ToStringBuilder.reflectionToString(pgpCompressedData));
		mLogger.debug("[LOG][pgpCompressedData.Algorithm(壓縮格式)]" + FoyaAlgorithm.pgpCompressedDataAlgorithmTags(pgpCompressedData.getAlgorithm()));

		mLogger.debug("[LOG] 3 s-------------");
		// 解壓縮
		byte[] dataStreamBytes = this.inputStream2BytesLog(pgpCompressedData.getDataStream());
		mLogger.debug("[LOG] 3 e-------------");

		// 把解壓縮完的資料丟入工廠處理

		JcaPGPObjectFactory masterFactory = new JcaPGPObjectFactory(new ByteArrayInputStream(dataStreamBytes));

		/**
		 * 1
		 */
		PGPOnePassSignatureList pgpOnePassSignatureList = (PGPOnePassSignatureList) masterFactory.nextObject();
		PGPOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList.iterator().next();

		long keyID = pgpOnePassSignature.getKeyID();
		mLogger.debug("[LOG][getKeyID][檔案裡面的key id]" + keyID);

		mLogger.debug("[LOG][getKeyAlgorithm]" + FoyaAlgorithm.publicKeyAlgorithmTags(pgpOnePassSignature.getKeyAlgorithm()));
		mLogger.debug("[LOG][getHashAlgorithm]" + FoyaAlgorithm.publicKeyAlgorithmTags(pgpOnePassSignature.getHashAlgorithm()));
		mLogger.debug("[LOG][getSignatureType]" + pgpOnePassSignature.getSignatureType());
		mLogger.debug("[LOG][pgpOnePassSignature]" + ToStringBuilder.reflectionToString(pgpOnePassSignature));
		/**
		 * 2
		 */
		PGPLiteralData pgpLiteralData = (PGPLiteralData) masterFactory.nextObject();

		mLogger.debug("[LOG] 4 s-------------");
		byte[] dInBytes = this.inputStream2BytesLog(pgpLiteralData.getInputStream());
		mLogger.debug("[LOG] 4 e-------------");
		// public key
		PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyIn), new JcaKeyFingerprintCalculator());

		// 用keyid找key
		PGPPublicKey key = pgpRing.getPublicKey(keyID);

		publicKeyInfo(key);

		// verify init
		pgpOnePassSignature.init(new JcaPGPContentVerifierBuilderProvider(), key);
		for (int i = 0; i < dInBytes.length; i++) {
			//verify
			pgpOnePassSignature.update(dInBytes[i]);
		}
		/**
		 * 3
		 */
		PGPSignatureList pgpSignatureList = (PGPSignatureList) masterFactory.nextObject();

		if (pgpOnePassSignature.verify(pgpSignatureList.get(0))) {
			mLogger.debug("[LOG]***********[signature verified]***********");
			mLogger.debug("[LOG]***********[signature verified]***********");
			mLogger.debug("[LOG]***********[signature verified]***********");
			mLogger.debug("[LOG]***********[signature verified]***********");
			mLogger.debug("[LOG]***********[signature verified]***********");

			// to file
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

	public void publicKeyInfo(String publicKeyFileName) throws FileNotFoundException, IOException, PGPException {
		FileInputStream publicKeyIn = new FileInputStream(publicKeyFileName);
		PGPPublicKey pgpPublicKey = PGPUtils.readPublicKey(publicKeyIn);
		publicKeyInfo(pgpPublicKey);
	}

	@SuppressWarnings("rawtypes")
	public PublicKey publicKeyInfo(PGPPublicKey pgpPublicKey) throws FileNotFoundException, IOException, PGPException {

		mLogger.debug(ToStringBuilder.reflectionToString(pgpPublicKey, ToStringStyle.MULTI_LINE_STYLE));
		mLogger.debug("-----------");
		mLogger.debug(ToStringBuilder.reflectionToString(pgpPublicKey.getPublicKeyPacket(), ToStringStyle.MULTI_LINE_STYLE));
		mLogger.debug("-----------");

		Iterator signatures = pgpPublicKey.getSignatures();
		while (signatures.hasNext()) {
			mLogger.debug(ToStringBuilder.reflectionToString(signatures.next(), ToStringStyle.MULTI_LINE_STYLE));
		}
		mLogger.debug("-----------");

		// find out a little about the keys in the public key ring
		mLogger.debug("Key Strength = " + pgpPublicKey.getBitStrength());
		mLogger.debug("Algorithm = " + FoyaAlgorithm.publicKeyAlgorithmTags(pgpPublicKey.getAlgorithm()));
		mLogger.debug("Bit strength = " + pgpPublicKey.getBitStrength());
		mLogger.debug("Version = " + pgpPublicKey.getVersion());
		mLogger.debug("Encryption key = " + pgpPublicKey.isEncryptionKey() + ", Master key = " + pgpPublicKey.isMasterKey());
		mLogger.debug("Fingerprint: " + new String(Hex.encode(pgpPublicKey.getFingerprint())));
		int count = 0;
		for (Iterator iterator = pgpPublicKey.getUserIDs(); iterator.hasNext();) {
			count++;
			mLogger.debug((String) iterator.next());
		}
		mLogger.debug("Key Count = " + count);

		mLogger.debug("---publicKey--------");

		PublicKey publicKey = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider()).getPublicKey(pgpPublicKey);
		return publicKey;
	}

	private byte[] inputStream2BytesLog(InputStream signSourceIn) throws IOException {
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		IOUtils.copy(signSourceIn, bao);
		byte[] signSourceInBytes = bao.toByteArray();
		String signSourceInString = IOUtils.toString(new ByteArrayInputStream(signSourceInBytes), StandardCharsets.UTF_8.name());
		mLogger.debug(signSourceInString);
		return signSourceInBytes;
	}

	@Test
	public void verifyAndDecrypt() {
		try {
			FileInputStream in = new FileInputStream(new File("e:/tmp/123.encrypt.sign.txt"));
			//			FileInputStream in = new FileInputStream(new File("e:/tmp/123.encrypt.sign.error.txt"));
			FileInputStream pKeyIn = new FileInputStream(new File("F:/foya/02.tommy4Git/gpg/src/main/resources/tstar_public.asc"));
			verifyFile(in, pKeyIn, "C:/Users/tommy/Desktop/123.verify.sign.txt");

			in.close();
			pKeyIn.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	@Test
	public void publicKeyInfoTest() {
		try {
			publicKeyInfo("F:/foya/02.tommy4Git/gpg/src/main/resources/tstar_public.asc");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}




}
