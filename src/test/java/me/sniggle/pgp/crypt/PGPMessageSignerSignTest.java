package me.sniggle.pgp.crypt;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.*;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertTrue;

/**
 * Created by iulius on 19/09/15.
 */
@RunWith(Parameterized.class)
public class PGPMessageSignerSignTest {

  private final String userId;
  private final String privateKeyFilename;
  private final String messageFilename;
  private final String publicKeyFilename;
  private MessageSigner messageSigner;

  public PGPMessageSignerSignTest(String userId, String privateKeyFilename, String publicKeyFilename, String messageFilename ) {
    this.userId = userId;
    this.privateKeyFilename = privateKeyFilename;
    this.publicKeyFilename = publicKeyFilename;
    this.messageFilename = messageFilename;
  }

  @Parameterized.Parameters
  public static Collection<Object[]> data() {
    return Arrays.asList(new Object[][]{
        { "Test Case 1 (PGP key for simple-pgp testcase) <testcase-1@sniggleme.info>", "testcase-1-sec.asc", "testcase-1-pub.asc", "test-message.txt" },
        { "Test Case 2 (PGP key for test case of simple-pgp) <testcase-2@sniggleme.info>", "testcase-2-sec.asc", "testcase-2-pub.asc", "test-message.txt" }
    });
  }

  @Before
  public void setUp() throws Exception {
    messageSigner = PGPWrapperFactory.getSigner();
  }

  @Test
  public void testSignMessage() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    assertTrue(messageSigner.signMessage(getClass().getResourceAsStream(privateKeyFilename), userId, "testpassword", getClass().getResourceAsStream(messageFilename), baos));
    assertTrue(messageSigner.verifyMessage(getClass().getResourceAsStream(publicKeyFilename), getClass().getResourceAsStream(messageFilename), new ByteArrayInputStream(baos.toByteArray())));
  }

  @After
  public void tearDown() throws Exception {
    messageSigner = null;

  }
}
