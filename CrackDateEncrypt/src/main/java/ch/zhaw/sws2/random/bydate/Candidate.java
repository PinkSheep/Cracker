package ch.zhaw.sws2.random.bydate;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**<p>Stores parameters used for a candidate key in the 
 * brute forcing process together with the resulting
 * output data and a number representing a kind of 
 * rating of the candidate. The rating should allow to 
 * assess how "likely" this candidate contains the 
 * parameters used for the encryption process.</p>  
 * 
 * <p>Useful to store promising results that a human 
 * can look at when the brute forcing process has ended.<p> 
 *  
 * @author Bernhard Tellenbach &lt;tebe@zhaw.ch&gt;
 * @version 1.0
 * @date 2016-03-06
 */
public class Candidate {
  private static final int MAX_PLAINTEXT_RETURN = 50;
  private final byte[] buffer;
  private final double rating;
  private final long secondsSinceEpoch;
  private final int usecs;

  
  /**Constructor.
   * @param system system used to decrypt the data
   * @param buffer decrypted data
   * @param rating rating of this candidate 
   */
  public Candidate(MySystem system, byte[] buffer, double rating) {
    this.buffer = Arrays.copyOf(buffer,buffer.length);
    this.secondsSinceEpoch = system.getSecondsSinceEpoch();
    this.usecs = system.getUsecs();
    this.rating = rating;
  }

  /**
   * @return the entropy of this candidate
   */
  public double getRating() {
    return rating;
  }

  @Override
  public String toString() {
    
    return "Candidate [ secondsSinceEpoch=" + secondsSinceEpoch 
        + ", usecs=" + usecs + ", rating=" + rating + ", buffer=" 
        + new String(Arrays.copyOf(buffer,  
            MAX_PLAINTEXT_RETURN), StandardCharsets.UTF_8) + "]";
  }
}
