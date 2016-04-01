package com.foya.gpg.tool;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.junit.Test;

import com.foya.gpg.ok.tool.PGPUtils;

public class EncryptFile4PublicKey {

	@Test
	public void testEncrypt() throws Exception {
		FileInputStream keyIn = new FileInputStream("F:/foya/02.tommy4Git/gpg/src/main/resources/tommy_public.asc");
		OutputStream encrptFileName = new FileOutputStream(new File("C:/Users/tommy/Desktop/123.en.txt"));
		String inputFileName = "e:/123.txt";
		PGPPublicKey encKey = PGPUtils.readPublicKey(keyIn);
		boolean asciiArmored = true;
		boolean integrityCheck = true;

		encryptFile(encrptFileName, inputFileName, encKey, asciiArmored, integrityCheck, PGPCompressedData.BZIP2, PGPEncryptedData.TRIPLE_DES,
				PGPLiteralData.UTF8);

	}

	public boolean encryptFile(OutputStream encrptFileName, String fileName, PGPPublicKey encKey, boolean armor, boolean withIntegrityCheck,
			int algorithm, int encAlgorithm, char fileType) {

		Security.addProvider(new BouncyCastleProvider());

		if (armor) {
			encrptFileName = new ArmoredOutputStream(encrptFileName);
		}
		ByteArrayOutputStream bOut = null;
		OutputStream cOut = null;
		PGPCompressedDataGenerator comData = null;
		try {
			bOut = new ByteArrayOutputStream();
			comData = new PGPCompressedDataGenerator(algorithm);

			PGPUtil.writeFileToLiteralData(comData.open(bOut), fileType, new File(fileName));

			BcPGPDataEncryptorBuilder dataEncryptor = new BcPGPDataEncryptorBuilder(encAlgorithm);
			dataEncryptor.setWithIntegrityPacket(withIntegrityCheck);
			dataEncryptor.setSecureRandom(new SecureRandom());

			PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
			encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));
			byte[] bytes = bOut.toByteArray();
			cOut = encryptedDataGenerator.open(encrptFileName, bytes.length);
			cOut.write(bytes);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			if (comData != null) {
				try {
					comData.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			IOUtils.closeQuietly(cOut);
			IOUtils.closeQuietly(bOut);
		}

		return true;
	}

}
