package com.foya.gpg.tool;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.junit.Test;

import com.foya.gpg.ok.tool.PGPUtils;

public class EncryptFile4PublicKey {

	@Test
	public void testEncrypt02() throws Exception {



	}

	@Test
	public void testEncrypt() throws Exception {
		FileInputStream keyIn = new FileInputStream("F:/foya/02.tommy4Git/gpg/src/main/resources/tommy_public.asc");
		OutputStream out = new FileOutputStream(new File("C:/Users/tommy/Desktop/123.en.txt"));
		String inputFileName = "e:/123.txt";
		PGPPublicKey encKey = PGPUtils.readPublicKey(keyIn);
		boolean asciiArmored = true;
		boolean integrityCheck = false;

		encryptFile(out, inputFileName, encKey , asciiArmored, integrityCheck);











	}
	public static void encryptFile(OutputStream out, String fileName, PGPPublicKey encKey, boolean armor, boolean withIntegrityCheck)
			throws IOException, NoSuchProviderException, PGPException {
		Security.addProvider(new BouncyCastleProvider());

		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.BZIP2);

		PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));

		comData.close();

		BcPGPDataEncryptorBuilder dataEncryptor = new BcPGPDataEncryptorBuilder(PGPEncryptedData.TRIPLE_DES);
		dataEncryptor.setWithIntegrityPacket(withIntegrityCheck);
		dataEncryptor.setSecureRandom(new SecureRandom());

		PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
		encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));

		byte[] bytes = bOut.toByteArray();
		OutputStream cOut = encryptedDataGenerator.open(out, bytes.length);
		cOut.write(bytes);
		cOut.close();
		out.close();
	}


}
