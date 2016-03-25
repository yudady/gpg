package com.foya.gpg.ok.sign;

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

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import com.foya.gpg.examples.PGPExampleUtil;

/**
 * A simple utility class that signs and verifies files.
 * <p>
 * To sign a file: SignedFileProcessor -s [-a] fileName secretKey passPhrase.<br>
 * If -a is specified the output file will be "ascii-armored".
 * <p>
 * To decrypt: SignedFileProcessor -v fileName publicKeyFile.
 * <p>
 * <b>Note</b>: this example will silently overwrite files, nor does it pay any attention to the specification of "_CONSOLE" in the filename. It also expects that a single pass phrase will have been used.
 * <p>
 * <b>Note</b>: the example also makes use of PGP compression. If you are having difficulty getting it to interoperate with other PGP programs try removing the use of compression first.
 */
public class SignedFileProcessorTommy {
	/* verify the passed in file as being correctly signed. */
	public static void verifyFile(InputStream in, InputStream keyIn, OutputStream out) throws Exception {
		in = PGPUtil.getDecoderStream(in);

		JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);

		PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();

		pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

		PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();

		PGPOnePassSignature ops = p1.get(0);

		PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

		InputStream dIn = p2.getInputStream();
		int ch;
		PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

		PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());

		ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

		while ((ch = dIn.read()) >= 0) {
			ops.update((byte) ch);
			out.write(ch);
		}

		out.close();

		PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

		if (ops.verify(p3.get(0))) {
			System.out.println("signature verified.");
		} else {
			System.out.println("signature verification failed.");
		}
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
	public static void signFile(String fileName, InputStream keyIn, OutputStream out, char[] pass, boolean armor)
			throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {
		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		PGPSecretKey pgpSec = PGPExampleUtil.readSecretKey(keyIn);
		PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
		PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

		sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

		Iterator it = pgpSec.getPublicKey().getUserIDs();
		if (it.hasNext()) {
			PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

			spGen.setSignerUserID(false, (String) it.next());
			sGen.setHashedSubpackets(spGen.generate());
		}

		PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);

		BCPGOutputStream bOut = new BCPGOutputStream(cGen.open(out));

		sGen.generateOnePassVersion(false).encode(bOut);

		File file = new File(fileName);
		PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
		OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, file);
		FileInputStream fIn = new FileInputStream(file);
		int ch;

		while ((ch = fIn.read()) >= 0) {
			lOut.write(ch);
			sGen.update((byte) ch);
		}

		lGen.close();

		sGen.generate().encode(bOut);

		cGen.close();

		if (armor) {
			out.close();
		}
	}

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		FileInputStream keyIn = new FileInputStream(new File("F:/foya/00.work/gpg/src/main/resources/secring.gpg"));
		FileOutputStream out = new FileOutputStream("e:/123.en.asc");

		signFile("e:/123.txt", keyIn, out, "tommy".toCharArray(), true);

		FileInputStream in = new FileInputStream(new File("e:/123.en.asc"));
		FileInputStream pKeyIn = new FileInputStream(new File("F:/foya/00.work/gpg/src/main/resources/pubring.gpg"));
		FileOutputStream outVerify = new FileOutputStream(new File("e:/123.de.txt"));
		verifyFile(in, pKeyIn, outVerify);

		keyIn.close();
		pKeyIn.close();
		out.close();
		outVerify.close();

	}
}