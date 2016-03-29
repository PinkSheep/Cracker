package ch.zhaw.sws2.random.bydate;

import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.SecretKeySpec;

/** A previous version of the Netscape cryptographic key generator.
 *
 * @author Stephan Neuhaus &lt;stephan.neuhaus@zhaw.ch&gt;
 * @author Bernhard Tellenbach &lt;tebe@zhaw.ch&gt;
 * @version 1.1
 * @date 2016-03-06
 */
public class NetscapeKeygen {
  private byte[] key;
  private byte[] iv;
  private String cipherAlgorithm;
  private MySystem system;

  /** Constructs a key generator "the Netscape way"
   * @param system the system used to get time and pid information
   * @param cipherAlgorithm the cipher algorithm to generate keys for
   */
  public NetscapeKeygen(MySystem system, String cipherAlgorithm) {
    this.key = null;
    this.iv = null;
    this.cipherAlgorithm = cipherAlgorithm;
    this.system = system;
  }

  private static long mixbits(long input) {
    return (314192565L * input + 2718289L) % (1L << Integer.SIZE);
  }

  /**
   * Threats the argument as a base-256 unsigned integer and increments it.
   *
   * @param buf
   *          a byte buffer, treated as a base-256 unsigned integer
   */
  private static void doInc(byte[] buf) {
    /*
     * Incrementing an integer in positional notation is perhaps best understood
     * by looking at how we increment a base-10 integer. The algorithm is very
     * simple:
     *
     * Step 1: Start at the least-significant digit. Step 2: Is the current
     * digit not 9? If so, go to Step 4. (At this point, the current digit is
     * 9.) Set the current digit to 0. Step 3. Proceed to the next more
     * significant digit. If that is not possible, terminate the algorithm (the
     * input was 999...9, which has now overflowed). Otherwise return to Step 2.
     * Step 4: Increment the current digit and terminate the algorithm.
     *
     * Examples:
     *
     * 1. The input "901" takes us to Step 4, where the least significant digit
     * is incremented and the algorithm terminated with the answer "902".
     *
     * 2. The input "199" takes us to Steps 2 and 3, where the least significant
     * digit is set to 0 (intermediate result "190"), then the middle digit is
     * also set to 0 (intermediate result "100") and finally (Step 4) the most
     * significant digit is incremented and the algorithm terminated (final
     * result "200").
     *
     * Incrementing a base-256 digit is essentially the same, just replace "9"
     * by "255". In the general case of incrementing a base-b number, replace
     * "9" by "b - 1", and in the even more general case of mixed- radix
     * notation, replace "9" by "b[i] - 1". For example, in the base-60-60-24
     * notation of wall-clock time, incrementing 16:59:58 yields 16:59:59, and
     * 16:59:59 yields 17:00:00.
     *
     * We're taking slight liberties with the algorithm above. We're also
     * assuming that "buffer" is big-endian, i.e., index 0 has the most
     * significant digit.
     */
    int i = buf.length - 1;
    while (i >= 0 && buf[i] == Byte.MAX_VALUE) {
      buf[i] = 0;
      i--;
    }

    if (i >= 0) {
      buf[i]++;
    }
  }

  /** Generates key and iv using current system info 
   * @throws NoSuchAlgorithmException
   * @throws InvalidParameterSpecException
   */
  public void makeKey() throws NoSuchAlgorithmException,
      InvalidParameterSpecException {
    long one = mixbits(system.getUsecs());
    long two = mixbits(system.getpid() + system.getSecondsSinceEpoch()
        + (system.getppid() << 12));

    byte[] seed = doMD5(one, two);

    iv = doMD5(seed);
    doInc(seed);

    key = doMD5(seed);
    doInc(seed);

  }

  private static byte[] doMD5(long one, long two) {
    byte[] input = new byte[2 * Integer.SIZE / Constants.BITS_PER_BYTE];

    for (int i = 0; i < Integer.SIZE / Constants.BITS_PER_BYTE; i++) {
      input[i] = (byte) (one & 0xff);
      one >>= 8;
    }

    for (int i = 0; i < Integer.SIZE / Constants.BITS_PER_BYTE; i++) {
      input[Integer.SIZE / Constants.BITS_PER_BYTE + i] = (byte) (two & 0xff);
      two >>= 8;
    }

    MessageDigest digest;
    try {
      digest = MessageDigest.getInstance(Constants.MD5_DIGEST_NAME);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("MD5 unknown??");
    }
    return digest.digest(input);
  }

  private static byte[] doMD5(byte[] input) {
    MessageDigest digest;
    try {
      digest = MessageDigest.getInstance(Constants.MD5_DIGEST_NAME);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("MD5 unknown??");
    }
    return digest.digest(input);
  }

  public byte[] getKey() {
    return key;
  }

  public byte[] getIv() {
    return iv;
  }

  public SecretKeySpec getSecretKeySpec() {
    return new SecretKeySpec(key, cipherAlgorithm);
  }

  public AlgorithmParameters getAlgorithmParameters()
      throws NoSuchAlgorithmException,
             InvalidParameterSpecException {
    return AlgorithmParameters.getInstance(cipherAlgorithm);
  }

}
