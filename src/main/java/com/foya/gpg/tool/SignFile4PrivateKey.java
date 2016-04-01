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

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.junit.Test;

import com.foya.gpg.examples.PGPExampleUtil;
import com.foya.gpg.ok.tool.PGPFileProcessor;
import com.foya.gpg.ok.tool.PGPUtils;

public class SignFile4PrivateKey {

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
	private static void signFile(String fileName, InputStream keyIn, OutputStream out, char[] pass, boolean armor)
			throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {
		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		PGPSecretKey pgpSec = PGPExampleUtil.readSecretKey(keyIn);
		PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(new BouncyCastleProvider()).build(pass));


		int algorithm = pgpSec.getPublicKey().getAlgorithm();

		PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(algorithm, PGPUtil.SHA1).setProvider(new BouncyCastleProvider()));

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

	@Test
	public void testSign() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		FileInputStream keyIn = new FileInputStream(new File("F:/foya/02.tommy4Git/gpg/src/main/resources/tstar_private.asc"));
		FileOutputStream out = new FileOutputStream("C:/Users/tommy/Desktop/123.en.sign.txt");


		signFile("C:/Users/tommy/Desktop/123.en.txt", keyIn, out, "123456".toCharArray(), true);
	}



}
