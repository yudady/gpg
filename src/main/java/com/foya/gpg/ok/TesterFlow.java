package com.foya.gpg.ok;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import com.foya.gpg.ok.sign.SignedFileProcessorTommy;
import com.foya.gpg.ok.tool.PGPFileProcessor;

public class TesterFlow {

	private static final String TOMMY = "tommy";
	private static final String TSTAR = "123456";

	//	private static final String DE_INPUT = "e:/123.en.txt";
	//	private static final String DE_OUTPUT = "e:/123.de.txt";
	//
	//
	//	private static final String E_INPUT = "e:/123.txt";
	//	private static final String E_OUTPUT = "e:/123.en.txt";

	private static final String TOMMY_PRIVATE_KEY_PATH = "F:/foya/00.work/gpg/src/main/resources/tommy_private.asc";
	private static final String TOMMY_PUBLIC_KEY_PATH = "F:/foya/00.work/gpg/src/main/resources/tommy_public.asc";
	private static final String TSTAR_PRIVATE_KEY_PATH = "F:/foya/00.work/gpg/src/main/resources/tstar_private.asc";
	private static final String TSTAR_PUBLIC_KEY_PATH = "F:/foya/00.work/gpg/src/main/resources/tstar_public.asc";

	@Test
	public void testEncryptByTstarPublicKey() throws Exception {
		PGPFileProcessor p = new PGPFileProcessor();
		p.setInputFileName("e:/123.txt");
		p.setOutputFileName("e:/123.en.txt");
		p.setPublicKeyFileName(TSTAR_PUBLIC_KEY_PATH);
		System.out.println(p.encrypt());
	}

	@Test
	public void testSignByTommyPrivateKey() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		FileInputStream keyIn = new FileInputStream(new File(TOMMY_PRIVATE_KEY_PATH));
		FileOutputStream out = new FileOutputStream("e:/123.en.sign.txt");
		SignedFileProcessorTommy.signFile("e:/123.en.txt", keyIn, out, "tommy".toCharArray(), true);

		keyIn.close();
		out.close();

	}

	@Test
	public void testVerifyByTommyPublicKey() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		FileInputStream in = new FileInputStream(new File("e:/123.en.sign.txt"));
		FileInputStream pKeyIn = new FileInputStream(new File(TOMMY_PUBLIC_KEY_PATH));
		FileOutputStream outVerify = new FileOutputStream(new File("e:/123.verify.txt"));
		SignedFileProcessorTommy.verifyFile(in, pKeyIn, outVerify);
		pKeyIn.close();
	}

	@Test
	public void testDecryptTstarPrivateKey() throws Exception {
		PGPFileProcessor p = new PGPFileProcessor();
		p.setInputFileName("e:/123.verify.txt");
		p.setOutputFileName("e:/123.de.txt");
		p.setPassphrase(TSTAR);
		p.setSecretKeyFileName(TSTAR_PRIVATE_KEY_PATH);
		System.out.println(p.decrypt());
	}

}
