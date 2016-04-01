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
import me.sniggle.pgp.crypt.MessageSigner;
import me.sniggle.pgp.crypt.PGPMessageSigner;
import me.sniggle.pgp.crypt.PGPWrapperFactory;

public class PGPWrapperFactoryTest {

	private static String targerPath = System.getProperty("user.dir") + "/" + "target";
	private static String data = System.getProperty("user.dir") + "/src/test/resources/123.txt";

	@Test
	public void oneKey4Ency() throws FileNotFoundException {
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
	public void oneKey4Sign() throws FileNotFoundException {
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
			} catch (Exception e) {
				e.printStackTrace();
				throw e;
			} finally {
				IOUtils.closeQuietly(receiverPublicKeyFile);
				IOUtils.closeQuietly(receiverPriveteKeyFile);
			}
		}

		{
			MessageSigner signer = PGPWrapperFactory.getSigner();
			InputStream privateKeyOfSender = null;
			String userIdForPrivateKey = null;
			String passwordOfPrivateKey = null;
			InputStream message = null;
			OutputStream signature = null;

			try {

				privateKeyOfSender = new FileInputStream(new File(receiverPriveteKey));
				userIdForPrivateKey = receiverUserId;
				passwordOfPrivateKey = receiverPassword;
				message = new FileInputStream(new File(data));
				signature = new FileOutputStream(new File(targerPath + "/123.sign.txt"));

				boolean signMessage = signer.signMessage(privateKeyOfSender, userIdForPrivateKey, passwordOfPrivateKey, message, signature);
				System.out.println("[LOG]signMessage=>" + signMessage);
			} catch (Exception e) {
				e.printStackTrace();
				throw e;
			} finally {
				IOUtils.closeQuietly(privateKeyOfSender);
				IOUtils.closeQuietly(message);
				IOUtils.closeQuietly(signature);
			}
		}
		{
			MessageSigner signer = PGPWrapperFactory.getSigner();
			InputStream publicKeyOfSender = null;
			InputStream message = null;
			InputStream signatureStream = null;
			try {
				publicKeyOfSender = new FileInputStream(new File(receiverPublicKey));
				message = new FileInputStream(new File("e:/123.txt"));
				signatureStream = new FileInputStream(new File(targerPath + "/123.sign.txt"));
				boolean verifyMessage = signer.verifyMessage(publicKeyOfSender, message, signatureStream);
				System.out.println("[LOG]verifyMessage=>" + verifyMessage);
			} catch (Exception e) {
				e.printStackTrace();
				throw e;
			} finally {
				IOUtils.closeQuietly(publicKeyOfSender);
				IOUtils.closeQuietly(message);
				IOUtils.closeQuietly(signatureStream);
			}
		}

	}

	@Test
	public void twoKey4SenderReceiver() throws Exception {
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

		//sender key
		{
			OutputStream senderPublicKeyFile = null;
			OutputStream senderPriveteKeyFile = null;
			try {
				senderPublicKeyFile = new FileOutputStream(new File(senderPublicKey));
				senderPriveteKeyFile = new FileOutputStream(new File(senderPriveteKey));
				boolean generateKeyPair = keyPairGenerator.generateKeyPair(senderUserId, senderPassword, senderKeySize, senderPublicKeyFile, senderPriveteKeyFile);
				System.out.println("sender key : " + generateKeyPair);
			} finally {
				IOUtils.closeQuietly(senderPublicKeyFile);
				IOUtils.closeQuietly(senderPriveteKeyFile);
			}
		}

		// receiver key
		{

			OutputStream receiverPublicKeyFile = null;
			OutputStream receiverPriveteKeyFile = null;
			try {
				receiverPublicKeyFile = new FileOutputStream(new File(receiverPublicKey));
				receiverPriveteKeyFile = new FileOutputStream(new File(receiverPriveteKey));
				boolean generateKeyPair = keyPairGenerator.generateKeyPair(receiverUserId, receiverPassword, receiverKeySize, receiverPublicKeyFile, receiverPriveteKeyFile);
				System.out.println("receiver key : " + generateKeyPair);
			} finally {
				IOUtils.closeQuietly(receiverPublicKeyFile);
				IOUtils.closeQuietly(receiverPriveteKeyFile);
			}
		}

		// receiver public encoding
		{

			MessageEncryptor messageEncryptor = PGPWrapperFactory.getEncyptor();
			InputStream publicKeyOfRecipient = null;
			InputStream privateKeyOfSender = null;
			InputStream plainInputData = null;
			OutputStream target = null;
			try {
				publicKeyOfRecipient = new FileInputStream(new File(receiverPublicKey));
				privateKeyOfSender = new FileInputStream(new File(senderPriveteKey));
				String inputDataName = data;
				plainInputData = new FileInputStream(new File(data));
				target = new FileOutputStream(new File(targerPath + "/123.en.txt"));
				boolean encrypt = messageEncryptor.encrypt(publicKeyOfRecipient, inputDataName, plainInputData, target);
				System.out.println("[LOG]encrypt=>" + encrypt);
			} catch (Exception e) {
				e.printStackTrace();
				throw e;
			} finally {
				IOUtils.closeQuietly(publicKeyOfRecipient);
				IOUtils.closeQuietly(privateKeyOfSender);
				IOUtils.closeQuietly(plainInputData);
				IOUtils.closeQuietly(target);
			}
		}
		// sender privete sign
		{
			MessageSigner signer = PGPWrapperFactory.getSigner();
			InputStream privateKeyOfSender = null;
			String userIdForPrivateKey = null;
			String passwordOfPrivateKey = null;
			InputStream message = null;
			OutputStream signature = null;

			try {

				privateKeyOfSender = new FileInputStream(new File(senderPriveteKey));
				userIdForPrivateKey = senderUserId;
				passwordOfPrivateKey = senderPassword;
				message = new FileInputStream(new File(targerPath + "/123.en.txt"));
				signature = new FileOutputStream(new File(targerPath + "/123.en.sign.txt"));

				boolean signMessage = signer.signMessage(privateKeyOfSender, userIdForPrivateKey, passwordOfPrivateKey, message, signature);
				System.out.println("[LOG]signMessage=>" + signMessage);
			} catch (Exception e) {
				e.printStackTrace();
				throw e;
			} finally {
				IOUtils.closeQuietly(privateKeyOfSender);
				IOUtils.closeQuietly(message);
				IOUtils.closeQuietly(signature);
			}
		}

		// sender public verify
		{

			PGPMessageSigner signer = new PGPMessageSigner();

			InputStream publicKeyOfSender = null;
			InputStream message = null;
			InputStream signatureStream = null;

			try {
				publicKeyOfSender = new FileInputStream(new File(senderPublicKey));
				message = new FileInputStream(new File(targerPath + "/123.en.txt"));
				signatureStream = new FileInputStream(new File(targerPath + "/123.en.sign.txt"));
				boolean verifyMessage = signer.verifyMessage(publicKeyOfSender, message, signatureStream);
				System.out.println("[LOG]verifyMessage=>" + verifyMessage);
			} catch (Exception e) {
				e.printStackTrace();
				throw e;
			} finally {
				IOUtils.closeQuietly(publicKeyOfSender);
				IOUtils.closeQuietly(message);
				IOUtils.closeQuietly(signatureStream);
			}
		}

		//receiver private decoding
		{

			MessageEncryptor messageEncryptor = PGPWrapperFactory.getEncyptor();
			InputStream privateKeyOfReceiver = null;
			InputStream publicKeyOfSender = null;
			InputStream encryptedData = null;
			OutputStream target = null;
			try {
				String passwordOfReceiversPrivateKey = receiverPassword;
				privateKeyOfReceiver = new FileInputStream(new File(receiverPriveteKey));
				encryptedData = new FileInputStream(new File(targerPath + "/123.en.txt"));
				target = new FileOutputStream(new File(targerPath + "/123.de.verify.txt"));

				messageEncryptor.decrypt(passwordOfReceiversPrivateKey, privateKeyOfReceiver, encryptedData, target);

			} catch (Exception e) {
				e.printStackTrace();
				throw e;
			} finally {
				IOUtils.closeQuietly(privateKeyOfReceiver);
				IOUtils.closeQuietly(publicKeyOfSender);
				IOUtils.closeQuietly(encryptedData);
				IOUtils.closeQuietly(target);
			}
		}
	}

}
