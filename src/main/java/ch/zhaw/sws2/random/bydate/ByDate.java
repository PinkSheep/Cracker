package ch.zhaw.sws2.random.bydate;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Random;
import java.util.TimeZone;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Encrypts or decrypts a file using the provided parameters
 *
 *<p>Usage: ByDate encrypt|decrypt cipher timespec usec in out</p>
 *
 *<p>encrypt  encrypt the input file
 * decrypt  decrypt the input file
 * cipher   a cipher specification like DES/CBC/NoPadding
 * timespec a local date and time in the form 2011-12-03T10:15:30+01:00,
 *          i.e., a date and time with an integer time zone offset. In this
 *          example, the offset indicates a time zone that is one hour east
 *          of UTC.  In technical terms, the input must be parseable by a
 *          {@link DateTimeFormatter.ISO_OFFSET_DATE_TIME}.
 * usec     microseconds offset from timespec 
 * in       a file name to be encrypted. It is a fatal error if the file
 *          does not already exist, cannot be opened for reading or at
 *          any point cannot be read.
 * out      name of the output file.  Preexisting files are silently
 *          overwritten.  It is a fatal error if the file cannot be opened
 *          for writing or at any point cannot be written.</p>
 *
 * @author Stephan Neuhaus &lt;stephan.neuhaus@zhaw.ch&gt;
 * @author Bernhard Tellenbach &lt;tebe@zhaw.ch&gt;
 * @version 1.1
 * @date 2016-03-06
 */
public class ByDate {
  enum Mode {
    ENCRYPT, DECRYPT
  }
  
  /** Buffer size used for encryption/decryption */
  private static final int BUFFER_SIZE = 1024;

  private Mode mode;
  private String cipherSpec;
  private String cipherAlgorithm;
  private String infileName;
  private String outfileName;
  private MySystem system;


  private ByDate(String modeString, String cipherSpec, MySystem system,
      String infileName, String outfileName)
          throws NoSuchAlgorithmException,
                 NoSuchPaddingException,
                 InvalidParameterSpecException {
    if ("encrypt".startsWith(modeString)) {
      mode = Mode.ENCRYPT;
    } else if ("decrypt".startsWith(modeString)) {
      mode = Mode.DECRYPT;
    } else {
      throw new IllegalArgumentException(
          String.format("First argument must be a prefix of either "
              + "\"encrypt\" or \"decrypt\", got %s", modeString));
    }
    assert mode == Mode.DECRYPT || mode == Mode.ENCRYPT;

    printInterceptTime(system.getDateTime(), TimeZone.getTimeZone("Europe/Zurich"), infileName);

    this.cipherSpec = cipherSpec;
    this.cipherAlgorithm = getCipherAlgorithmFromSpec();
    this.infileName = infileName;
    this.outfileName = outfileName;
    this.system = system;
  }


  private void printInterceptTime(ZonedDateTime date, TimeZone timeZone, String infileName) {
    ZonedDateTime local = date.withZoneSameInstant(timeZone.toZoneId());
    System.out.println("Intercept time for " + infileName + ": " + local);
  }

  private void work()
      throws IllegalStateException,
             IOException,
             InvalidKeyException,
             InvalidAlgorithmParameterException,
             NoSuchAlgorithmException,
             NoSuchPaddingException,
             InvalidParameterSpecException {
    try (FileInputStream is = new FileInputStream(new File(infileName));
        FileOutputStream os = new FileOutputStream(new File(outfileName))) {

      switch (mode) {
        case ENCRYPT: encryptFile(is, os); 
          break;
        case DECRYPT: decryptFile(is, os); 
          break;
        default:
          throw new IllegalStateException(
              "Unknown mode of operation: " + mode.toString());
      }
    }
  }


  private String getCipherAlgorithmFromSpec() {
    return cipherSpec.split("/")[0];
  }

  private void encryptFile(InputStream is, OutputStream os)
      throws NoSuchAlgorithmException,
             InvalidParameterSpecException,
             NoSuchPaddingException,
             InvalidKeyException,
             InvalidAlgorithmParameterException,
             IOException {
    NetscapeKeygen keygen = new NetscapeKeygen(system, cipherAlgorithm);
    keygen.makeKey();

    Cipher cipher = Cipher.getInstance(cipherSpec);

    AlgorithmParameters algParam = keygen.getAlgorithmParameters();
    algParam.init(new IvParameterSpec(keygen.getIv()));

    SecretKeySpec skeySpec = keygen.getSecretKeySpec();
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, algParam);

    assert cipher.getBlockSize() > 0;
    assert cipher.getBlockSize() == keygen.getIv().length;

    os.write(keygen.getIv());
    os.flush();
    processStream(is, os, cipher);
  }

  private void decryptFile(InputStream is, OutputStream os)
      throws NoSuchAlgorithmException,
             InvalidParameterSpecException,
             NoSuchPaddingException,
             InvalidKeyException,
             InvalidAlgorithmParameterException,
             IOException {
    NetscapeKeygen keygen = new NetscapeKeygen(system, cipherAlgorithm);
    keygen.makeKey();

    Cipher cipher = Cipher.getInstance(cipherSpec);
    SecretKeySpec skeySpec = keygen.getSecretKeySpec();
    
    AlgorithmParameters algParam = null;
    if (isModeRequiringIv()) {
      // We have an AES mode with an IV
      algParam = keygen.getAlgorithmParameters();
      algParam.init(new IvParameterSpec(keygen.getIv()));
    }
    cipher.init(Cipher.DECRYPT_MODE, skeySpec, algParam);

    assert cipher.getBlockSize() > 0;

    if (isModeRequiringIv()) {
      // We have an IV. Ignore the IV that we read because
      // we generated it already from time of day, pid, ppid, and so on.      
      byte[] newIv = new byte[cipher.getBlockSize()];
      is.read(newIv, 0, newIv.length);
    }
    processStream(is, os, cipher);
  }

  private boolean isModeRequiringIv() {
    return cipherSpec.contains("CBC") 
        || cipherSpec.contains("CTR")
        || cipherSpec.contains("GCM");
  }

  private void processStream(InputStream is, OutputStream os, Cipher cipher)
      throws IOException {
    try (CipherInputStream cis = new CipherInputStream(is, cipher)) {
      byte[] buffer = new byte[BUFFER_SIZE];

      int bytesRead = cis.read(buffer);
      while (bytesRead != -1) {
        os.write(buffer, 0, bytesRead);
        bytesRead = cis.read(buffer);
      }
      os.close();
    } catch (IOException e) {
      e.printStackTrace();
      throw e;
    }
  }

  /** The main method.
   *
   * @param args Command-line arguments; see class description for more.
   *
   * @throws InvalidParameterSpecException if the IV can't be used
   * @throws NoSuchPaddingException if the padding doesn't exist
   * @throws NoSuchAlgorithmException if the encryption algorithm doesn't exist
   * @throws IOException If a read or write operation fails
   * @throws InvalidAlgorithmParameterException  If the IV can't be used
   * @throws IllegalStateException If there is something wrong internally
   * @throws InvalidKeyException  If they key can't be used
   */
  public static void main(String[] args)
      throws NoSuchAlgorithmException,
             NoSuchPaddingException,
             InvalidParameterSpecException,
             InvalidKeyException,
             IllegalStateException,
             InvalidAlgorithmParameterException,
             IOException {
    if (args.length != 6) {
      throw new IllegalArgumentException(
          String.format("Need 6 arguments, got %d", args.length));
    }
    ZonedDateTime date = ZonedDateTime.parse(args[2]);
    long usecOffset = Long.parseLong(args[3]);

    MyFakeSystemImpl system = new MyFakeSystemImpl(
        date.toEpochSecond() * Constants.USECS_PER_SECOND + usecOffset, date.getZone());
    ByDate byDate = new ByDate(args[0], args[1], system, args[4], args[5]);
    byDate.work();
  }
}
