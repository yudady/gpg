package com.foya.sniggle;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import me.sniggle.pgp.crypt.KeyPairGenerator;
import me.sniggle.pgp.crypt.MessageEncryptor;
import me.sniggle.pgp.crypt.PGPWrapperFactory;

public class PGPWrapperFactoryTest {

	private static String targerPath = System.getProperty("user.dir") + "/" + "target";
	private static String data = System.getProperty("user.dir") + "/src/test/resources/123.txt";

	@Test
	public void oneKey4Receiver() throws FileNotFoundException {
		PGPWrapperFactory.init();

		String receiverUserId = "tommy";
		String receiverPassword = "tommy";
		String receiverPublicKey = targerPath + "/publicKey";
		String receiverPriveteKey = targerPath + "/priveteKey";
		int senderKeySize = 2048;
		{
			OutputStream receiverPublicKeyFile = null;
			OutputStream receiverPriveteKeyFile = null;
			try {
				KeyPairGenerator keyPairGenerator = PGPWrapperFactory.getKeyPairGenerator();
				receiverPublicKeyFile = new FileOutputStream(new File(receiverPublicKey));
				receiverPriveteKeyFile = new FileOutputStream(new File(receiverPriveteKey));
				boolean generateKeyPair = keyPairGenerator.generateKeyPair(receiverUserId, receiverPassword, senderKeySize, receiverPublicKeyFile, receiverPriveteKeyFile);
				System.out.println(generateKeyPair);
			} finally {
				IOUtils.closeQuietly(receiverPublicKeyFile);
				IOUtils.closeQuietly(receiverPriveteKeyFile);
			}
		}

		MessageEncryptor encyptor = PGPWrapperFactory.getEncyptor();

		{
			InputStream publicKeyOfRecipient = null;
			InputStream plainInputData = null;
			OutputStream target = null;
			try {
				publicKeyOfRecipient = new FileInputStream(new File(receiverPublicKey));
				String inputDataName = data;
				plainInputData = new FileInputStream(new File(data));
				target = new FileOutputStream(new File(targerPath + "/123.en.txt"));
				encyptor.encrypt(publicKeyOfRecipient, inputDataName, plainInputData, target);
			} finally {
				IOUtils.closeQuietly(publicKeyOfRecipient);
				IOUtils.closeQuietly(plainInputData);
				IOUtils.closeQuietly(target);
			}
		}

		{
			InputStream privateKeyOfReceiver = null;
			InputStream encryptedData = null;
			OutputStream target = null;
			try {
				String passwordOfReceiversPrivateKey = receiverPassword;
				privateKeyOfReceiver = new FileInputStream(new File(receiverPriveteKey));
				encryptedData = new FileInputStream(new File(targerPath + "/123.en.txt"));
				target = new FileOutputStream(new File(targerPath + "/123.de.txt"));
				encyptor.decrypt(passwordOfReceiversPrivateKey, privateKeyOfReceiver, encryptedData, target);
			} finally {
				IOUtils.closeQuietly(privateKeyOfReceiver);
				IOUtils.closeQuietly(encryptedData);
				IOUtils.closeQuietly(target);
			}
		}
	}

	@Test
	public void twoKey4SenderReceiver() throws FileNotFoundException {
		PGPWrapperFactory.init();
		KeyPairGenerator keyPairGenerator = PGPWrapperFactory.getKeyPairGenerator();
		String senderUserId = "yudady";
		String senderPassword = "yudady";
		String senderPublicKey = targerPath + "/senderPublicKey";
		String senderPriveteKey = targerPath + "/senderPriveteKey";
		String receiverUserId = "tstar";
		String receiverPassword = "tstar";
		String receiverPublicKey = targerPath + "/receiverPublicKey";
		String receiverPriveteKey = targerPath + "/receiverPriveteKey";
		int senderKeySize = 2048;
		int receiverKeySize = 1024;
		{
			OutputStream senderPublicKeyFile = null;
			OutputStream senderPriveteKeyFile = null;
			try {
				senderPublicKeyFile = new FileOutputStream(new File(senderPublicKey));
				senderPriveteKeyFile = new FileOutputStream(new File(senderPriveteKey));
				boolean generateKeyPair = keyPairGenerator.generateKeyPair(senderUserId, senderPassword, senderKeySize, senderPublicKeyFile, senderPriveteKeyFile);
				System.out.println(generateKeyPair);
			} finally {
				IOUtils.closeQuietly(senderPublicKeyFile);
				IOUtils.closeQuietly(senderPriveteKeyFile);
			}
		}
		{

			OutputStream receiverPublicKeyFile = null;
			OutputStream receiverPriveteKeyFile = null;
			try {
				receiverPublicKeyFile = new FileOutputStream(new File(receiverPublicKey));
				receiverPriveteKeyFile = new FileOutputStream(new File(receiverPriveteKey));
				boolean generateKeyPair = keyPairGenerator.generateKeyPair(receiverUserId, receiverPassword, receiverKeySize, receiverPublicKeyFile, receiverPriveteKeyFile);
				System.out.println(generateKeyPair);
			} finally {
				IOUtils.closeQuietly(receiverPublicKeyFile);
				IOUtils.closeQuietly(receiverPriveteKeyFile);
			}
		}

		MessageEncryptor messageEncryptor = PGPWrapperFactory.getEncyptor();

		{

			InputStream publicKeyOfRecipient = null;
			InputStream privateKeyOfSender = null;
			InputStream plainInputData = null;
			OutputStream target = null;
			try {
				publicKeyOfRecipient = new FileInputStream(new File(receiverPublicKey));
				privateKeyOfSender = new FileInputStream(new File(senderPriveteKey));
				String userIdOfSender = senderUserId;
				String passwordOfSendersPrivateKey = senderPassword;
				String inputDataName = data;
				plainInputData = new FileInputStream(new File(data));
				target = new FileOutputStream(new File(targerPath + "/123.en.sign.txt"));
				messageEncryptor.encrypt(publicKeyOfRecipient, privateKeyOfSender, userIdOfSender, passwordOfSendersPrivateKey, inputDataName, plainInputData, target);

			} finally {
				IOUtils.closeQuietly(publicKeyOfRecipient);
				IOUtils.closeQuietly(privateKeyOfSender);
				IOUtils.closeQuietly(plainInputData);
				IOUtils.closeQuietly(target);
			}
		}

		{

			InputStream privateKeyOfReceiver = null;
			InputStream publicKeyOfSender = null;
			InputStream encryptedData = null;
			OutputStream target = null;
			try {
				String passwordOfReceiversPrivateKey = receiverPassword;
				privateKeyOfReceiver = new FileInputStream(new File(receiverPriveteKey));
				publicKeyOfSender = new FileInputStream(new File(senderPublicKey));
				encryptedData = new FileInputStream(new File(targerPath + "/123.en.sign.txt"));
				target = new FileOutputStream(new File(targerPath + "/123.de.verify.txt"));
				messageEncryptor.decrypt(passwordOfReceiversPrivateKey, privateKeyOfReceiver, publicKeyOfSender, encryptedData, target);
			} finally {
				IOUtils.closeQuietly(privateKeyOfReceiver);
				IOUtils.closeQuietly(publicKeyOfSender);
				IOUtils.closeQuietly(encryptedData);
				IOUtils.closeQuietly(target);
			}
		}
	}

}
