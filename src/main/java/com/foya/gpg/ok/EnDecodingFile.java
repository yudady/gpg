package com.foya.gpg.ok;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

public class EnDecodingFile {

	//tommy_public.asc
	//dummy.asc
	static File publicKeyFile = new File("F:/foya/00.work/gpg/src/main/resources/dummy.asc");

	//tommy_private.asc
	//dummy.skr
	static File privateKeyFile = new File("F:/foya/00.work/gpg/src/main/resources/dummy.skr");

	static String target = "e:/123.txt";
	static String enTarget = "e:/123.en.txt";
	static String deTarget = "e:/123.de.txt";

	static char[] pass = "tommy".toCharArray();

	public static void main(String[] args) throws Exception {

		PGPPublicKey pubKey = readPublicKeyFromCol(new FileInputStream(publicKeyFile));
		encryptFile(new FileOutputStream(enTarget), target, pubKey);

		System.out.println("[LOG]=======================");

		decryptFile(new FileInputStream(enTarget), new FileInputStream(privateKeyFile), new FileInputStream(publicKeyFile), pass);

	}

	@SuppressWarnings("unchecked")
	public static void decryptFile(InputStream in, InputStream secKeyIn, InputStream pubKeyIn, char[] pass) throws IOException, PGPException, InvalidCipherTextException {
		Security.addProvider(new BouncyCastleProvider());

		PGPPublicKey pubKey = readPublicKeyFromCol(pubKeyIn);

		PGPSecretKey secKey = readSecretKeyFromCol(secKeyIn, pubKey.getKeyID());

		in = PGPUtil.getDecoderStream(in);

		JcaPGPObjectFactory pgpFact;

		PGPObjectFactory pgpF = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());

		Object o = pgpF.nextObject();
		PGPEncryptedDataList encList;

		if (o instanceof PGPEncryptedDataList) {

			encList = (PGPEncryptedDataList) o;

		} else {

			encList = (PGPEncryptedDataList) pgpF.nextObject();

		}

		Iterator<PGPPublicKeyEncryptedData> itt = encList.getEncryptedDataObjects();
		PGPPrivateKey sKey = null;
		PGPPublicKeyEncryptedData encP = null;
		while (sKey == null && itt.hasNext()) {
			encP = itt.next();
			secKey = readSecretKeyFromCol(new FileInputStream(privateKeyFile), encP.getKeyID());
			sKey = secKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass));
		}
		if (sKey == null) {
			throw new IllegalArgumentException("Secret key for message not found.");
		}

		InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));

		pgpFact = new JcaPGPObjectFactory(clear);

		PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();

		pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

		PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		InputStream inLd = ld.getDataStream();

		int ch;
		while ((ch = inLd.read()) >= 0) {
			bOut.write(ch);
		}

		//System.out.println(bOut.toString());

		bOut.writeTo(new FileOutputStream(deTarget));
		//return bOut;

	}

	public static void encryptFile(OutputStream out, String fileName, PGPPublicKey encKey) throws IOException, NoSuchProviderException, PGPException {
		Security.addProvider(new BouncyCastleProvider());

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

		PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));

		comData.close();

		PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES).setSecureRandom(new SecureRandom()));

		cPk.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));

		byte[] bytes = bOut.toByteArray();

		OutputStream cOut = cPk.open(out, bytes.length);

		cOut.write(bytes);

		cOut.close();

		out.close();
	}

	@SuppressWarnings("rawtypes")
	public static PGPPublicKey readPublicKeyFromCol(InputStream in) throws IOException, PGPException {
		in = PGPUtil.getDecoderStream(in);
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());
		PGPPublicKey key = null;
		Iterator rIt = pgpPub.getKeyRings();
		while (key == null && rIt.hasNext()) {
			PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
			Iterator kIt = kRing.getPublicKeys();
			while (key == null && kIt.hasNext()) {
				PGPPublicKey k = (PGPPublicKey) kIt.next();
				if (k.isEncryptionKey()) {
					key = k;
				}
			}
		}
		if (key == null) {
			throw new IllegalArgumentException("Can't find encryption key in key ring.");
		}
		return key;
	}

	public static PGPSecretKey readSecretKeyFromCol(InputStream in, long keyId) throws IOException, PGPException {
		in = PGPUtil.getDecoderStream(in);
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new BcKeyFingerprintCalculator());

		PGPSecretKey key = pgpSec.getSecretKey(keyId);

		if (key == null) {
			throw new IllegalArgumentException("Can't find encryption key in key ring.");
		}
		return key;
	}
}
