package ch.zhaw.sws2.random.bydate;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;


/**
 * Cracks the "Netscape encryption".
 *
 * <p>
 * Usage: Crack cipher timespec in
 * </p>
 *
 * <p>
 * cipher a cipher specification like DES/CBC/NoPadding 
 *        timespec a local date and time in the form 
 *        2011-12-03T10:15:30+01:00, i.e., a date and time with
 *        an integer time zone offset. In this example, 
 *        the offset indicates a time zone that is one hour east of UTC. 
 *        In technical terms, the input must be parseable by a 
 *        {@link DateTimeFormatter.ISO_OFFSET_DATE_TIME}.
 * in     a file name to be cracked. It is a fatal error if the file 
 *        does not already exist, cannot be opened for reading or at any 
 *        point cannot be read. 
 * </p>
 *
 * <p>
 * This program works as follows. It takes the timespec from the command line,
 * converts it to epoch seconds, and then brute-forces the
 * encrypted input file with candidate keys and stops when it finds a key that
 * appears to be the correct one.</p>
 * 
 * @author Bernhard Tellenbach &lt;tebe@zhaw.ch&gt;
 * @version 1.0
 * @date 2016-03-06
 */
public class Crack {
  
  /* Configuration */
  public static final int DECRYPT_MAX_BYTES = 2048;
  private String cipherSpec;
  private final String dateString;
  private byte[] encryptedData;

  /* TODO attributes, constants,... (if any)*/
  
  /**
   * Constructor. Reads {@link DECRYPT_MAX_BYTES} of 
   * encrypted data to be brute-forced.  
   * @param cipherSpec cipher specification like e.g., DES/CBC/NoPadding
   * @param dateString date string in {@link DateTimeFormatter.ISO_OFFSET_DATE_TIME} format
   * @param infileName name of the encrypted file
   */
  private Crack(String cipherSpec, String dateString, String infileName)
      throws NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidParameterSpecException, IOException {
    this.cipherSpec = cipherSpec;
    this.dateString = dateString;

    File inFile = new File(infileName);
    assert inFile.length() > 0;
    assert inFile.length() <= Integer.MAX_VALUE;
    this.encryptedData = new byte[Math.min(((int) inFile.length() - 16), DECRYPT_MAX_BYTES)];

    try (FileInputStream is = new FileInputStream(inFile)) {      
      handleIv(cipherSpec, is);
      long bytesRead = is.read(encryptedData);
      assert bytesRead == Math.min(encryptedData.length, DECRYPT_MAX_BYTES);
    }
  }

  /**Reads/Skips the IV if required.  
   * @param cipherSpec cipher specification (e.g., AES/ECB/NoPadding)
   * @param is input stream from which to read the iv (if any)
   * @throws IOException if I/O goes wrong
 * @throws InvalidParameterSpecException 
 * @throws NoSuchAlgorithmException 
 * @throws NoSuchPaddingException 
   */
  private void handleIv(String cipherSpec, FileInputStream is) 
      throws IOException, NoSuchPaddingException, NoSuchAlgorithmException {
	  
	  if (cipherSpec.contains("CBC") || cipherSpec.contains("CTR") || cipherSpec.contains("GCM")){
			is.skip(128);
	  }
  }

  private void work() {
    ArrayList<BruteForcer> bruteforcer = createBruteForcers();  
    bruteforcer.parallelStream().forEach((element) -> {
      try {
		element.run(encryptedData);
	} catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
    });
    for (BruteForcer element : bruteforcer) {
      Candidate candidate = element.getBestCandidate();
      System.out.println(candidate);
    }
  }
  
  private ArrayList<BruteForcer> createBruteForcers() {
    ArrayList<BruteForcer> bruteforcer = new ArrayList<BruteForcer>();
    
    /* TODO: Instantiate and configure one or multiple 
     *        BruteForcer Objects  */
    for (long second = -5; second < 5; second++) {
    	ZonedDateTime date = ZonedDateTime.parse(dateString).plusSeconds(second);
		BruteForcer bruteF = new BruteForcer(date, cipherSpec); 
		bruteforcer.add(bruteF);
	}
    return bruteforcer;
  }

  /**
   * The main method.
   *
   * @param args
   *          Command-line arguments; see class description for more.
   *
   * @throws InvalidParameterSpecException
   *           if the IV can't be used
   * @throws NoSuchPaddingException
   *           if the padding doesn't exist
   * @throws NoSuchAlgorithmException
   *           if the encryption algorithm doesn't exist
   * @throws IOException
   *           If a read or write operation fails
   * @throws IllegalStateException
   *           If there is something wrong internally
   */
  public static void main(String[] args) 
      throws NoSuchAlgorithmException, NoSuchPaddingException, 
      InvalidParameterSpecException, IOException {
  
    if (args.length != 3) {
      throw new IllegalArgumentException(String.format("Need 3 arguments, got %d", args.length));
    }
    Crack byDate = new Crack(args[0], args[1], args[2]);
    byDate.work();
  }
}
