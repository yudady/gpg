package com.foya.gpg.ok.tool;

import org.junit.Test;

public class TestEnDecrypt {

	private static final String PASSPHRASE = "tommy";

	private static final String DE_INPUT = "e:/123.en.txt";
	private static final String DE_OUTPUT = "e:/123.de.txt";
	//private static final String DE_KEY_FILE = "F:/foya/00.work/gpg/src/main/resources/dummy.skr";
	private static final String DE_KEY_FILE = "F:/foya/00.work/gpg/src/main/resources/tommy_private.asc";

	private static final String E_INPUT = "e:/123.txt";
	private static final String E_OUTPUT = "e:/123.en.txt";
	//private static final String E_KEY_FILE = "F:/foya/00.work/gpg/src/main/resources/dummy.asc";
	private static final String E_KEY_FILE = "F:/foya/00.work/gpg/src/main/resources/tommy_public.asc";

	@Test
	public void testEncrypt() throws Exception {
		PGPFileProcessor p = new PGPFileProcessor();
		p.setInputFileName(E_INPUT);
		p.setOutputFileName(E_OUTPUT);
		p.setPublicKeyFileName(E_KEY_FILE);
		System.out.println(p.encrypt());
	}

	@Test
	public void testDecrypt() throws Exception {
		PGPFileProcessor p = new PGPFileProcessor();
		p.setInputFileName(DE_INPUT);
		p.setOutputFileName(DE_OUTPUT);
		p.setPassphrase(PASSPHRASE);
		p.setSecretKeyFileName(DE_KEY_FILE);
		System.out.println(p.decrypt());
	}


}
