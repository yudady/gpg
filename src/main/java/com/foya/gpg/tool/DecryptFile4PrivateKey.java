package com.foya.gpg.tool;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import me.sniggle.pgp.crypt.MessageEncryptor;
import me.sniggle.pgp.crypt.PGPWrapperFactory;

public class DecryptFile4PrivateKey {

	private static final Logger mLogger = LoggerFactory.getLogger(DecryptFile4PrivateKey.class);



	@Test
	public void decrypt() throws Exception {
		String receiverPassword = "tommy";
		String receiverPriveteKey = "F:/foya/02.tommy4Git/gpg/src/main/resources/tommy_private.asc";
		InputStream privateKeyOfReceiver = null;
		InputStream encryptedData = null;
		OutputStream target = null;

		MessageEncryptor encyptor = PGPWrapperFactory.getEncyptor();
		try {
			String passwordOfReceiversPrivateKey = receiverPassword;
			privateKeyOfReceiver = new FileInputStream(new File(receiverPriveteKey));
			encryptedData = new FileInputStream(new File("C:/Users/tommy/Desktop/123.verify.sign.txt"));
			target = new FileOutputStream(new File("C:/Users/tommy/Desktop/123.verify.decrypt.txt"));
			encyptor.decrypt(passwordOfReceiversPrivateKey, privateKeyOfReceiver, encryptedData, target);
		} finally {
			IOUtils.closeQuietly(privateKeyOfReceiver);
			IOUtils.closeQuietly(encryptedData);
			IOUtils.closeQuietly(target);
		}
	}

}
