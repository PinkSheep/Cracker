package ch.zhaw.sws2.random.bydate;

import java.time.ZonedDateTime;

/** Providing time of day and process IDs.
 *
 * @author Stephan Neuhaus &lt;stephan.neuhaus@zhaw.ch&gt;
 * @author Bernhard Tellenbach &lt;tebe@zhaw.ch&gt;
 * @version 1.1
 * @date 2016-03-06
 */
public interface MySystem {
  /** Returns the process ID of this process.
   *
   * @return the process ID of this process
   */
  public int getpid();

  /** Returns the process ID of the parent process.
   *
   * @return the process ID of the parent process
   */
  public int getppid();

  /** Returns the seconds since midnight 1 January 1970, {@em local time}.
   *
   * @return the seconds since midnight 1 January 1970
   */
  public long getSecondsSinceEpoch();


  /** Returns the microseconds since the Epoch seconds.
   *
   * @return the microseconds since the Epoch seconds
   */
  public int getUsecs();

  public ZonedDateTime getDateTime();
}
