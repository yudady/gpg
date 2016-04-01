package com.foya.gpg.tool;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.foya.gpg.tool.algorithm.FoyaAlgorithm;

public class SignFile4PrivateKey {

	private static final Logger mLogger = LoggerFactory.getLogger(SignFile4PrivateKey.class);

	@Test
	public void testSign() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		FileInputStream keyIn = new FileInputStream(new File("F:/foya/02.tommy4Git/gpg/src/main/resources/tstar_private.asc"));
		FileOutputStream out = new FileOutputStream("C:/Users/tommy/Desktop/123.en.sign.txt");
		int hashAlgorithm = PGPUtil.SHA512;
		int signatureType = PGPSignature.CERTIFICATION_REVOCATION;
		int zipAlgorithm = PGPCompressedData.BZIP2;
		char format = PGPLiteralData.UTF8;
		signFile("C:/Users/tommy/Desktop/123.en.txt", keyIn, out, "123456".toCharArray(), true, hashAlgorithm, signatureType, zipAlgorithm, format);
	}

	/**
	 * Generate an encapsulated signed file.
	 *
	 * @param fileName
	 * @param keyIn
	 * @param out
	 * @param pass
	 * @param armor
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws PGPException
	 * @throws SignatureException
	 */
	@SuppressWarnings("rawtypes")
	private boolean signFile(String fileName, InputStream keyIn, OutputStream out, char[] pass, boolean armor, int hashAlgorithm, int signatureType,
			int zipAlgorithm, char format) {
		Security.addProvider(new BouncyCastleProvider());
		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		OutputStream lOut = null;
		OutputStream bOut = null;
		FileInputStream fIn = null;
		try {

			PGPSecretKey pgpSec = this.readSecretKey(keyIn);
			PGPPublicKey publicKey = pgpSec.getPublicKey();
			PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(pass));

			int keyAlgorithm = publicKey.getAlgorithm();
			mLogger.debug("[LOG][publicKey.algorithm]" + FoyaAlgorithm.publicKeyAlgorithmTags(keyAlgorithm));

			long publicKeyID = publicKey.getKeyID();
			mLogger.debug("[LOG][publicKeyID]" + publicKeyID);
			long privKeyID = pgpPrivKey.getKeyID();
			mLogger.debug("[LOG][privKeyID]" + privKeyID);

			// sign generator
			PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(keyAlgorithm, hashAlgorithm));
			// sign init
			pgpSignatureGenerator.init(signatureType, pgpPrivKey);

			Iterator it = publicKey.getUserIDs();
			if (it.hasNext()) {
				PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
				String userID = (String) it.next();
				spGen.setSignerUserID(true, userID);
				mLogger.debug("[LOG][userID]" + userID);
				pgpSignatureGenerator.setHashedSubpackets(spGen.generate());
			}

			// 壓縮
			PGPCompressedDataGenerator pgpCompressedDataGenerator = new PGPCompressedDataGenerator(zipAlgorithm);

			bOut = new BCPGOutputStream(pgpCompressedDataGenerator.open(out));

			PGPOnePassSignature pgpOnePassSignature = pgpSignatureGenerator.generateOnePassVersion(true);
			pgpOnePassSignature.encode(bOut);

			File file = new File(fileName);

			PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();

			lOut = lGen.open(bOut, format, file);
			fIn = new FileInputStream(file);
			int ch;

			while ((ch = fIn.read()) >= 0) {
				pgpSignatureGenerator.update((byte) ch);
				lOut.write(ch);
			}

			lGen.close();

			PGPSignature pgpSignature = pgpSignatureGenerator.generate();
			pgpSignature.encode(bOut);

			mLogger.debug("[LOG][pgpSignature.getHashAlgorithm()]" + FoyaAlgorithm.hashAlgorithmTags(pgpSignature.getHashAlgorithm()));
			mLogger.debug("[LOG][pgpSignature.getKeyAlgorithm()]" + FoyaAlgorithm.publicKeyAlgorithmTags(pgpSignature.getKeyAlgorithm()));

			pgpCompressedDataGenerator.close();

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			IOUtils.closeQuietly(bOut);
			IOUtils.closeQuietly(fIn);
			IOUtils.closeQuietly(out);
		}

		return true;
	}

	/**
	 * A simple routine that opens a key ring file and loads the first available key suitable for signature generation.
	 *
	 * @param input
	 *            stream to read the secret key ring collection from.
	 * @return a secret key.
	 * @throws IOException
	 *             on a problem with using the input stream.
	 * @throws PGPException
	 *             if there is an issue parsing the input stream.
	 */
	@SuppressWarnings("rawtypes")
	public PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

		Iterator keyRingIter = pgpSec.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

			Iterator keyIter = keyRing.getSecretKeys();
			while (keyIter.hasNext()) {
				PGPSecretKey key = (PGPSecretKey) keyIter.next();

				if (key.isSigningKey()) {
					return key;
				}
			}
		}

		throw new IllegalArgumentException("Can't find signing key in key ring.");
	}
}
