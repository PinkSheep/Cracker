package ch.zhaw.sws2.random.bydate;

/** Frequently used constants.
 *
 * @author Stephan Neuhaus &lt;stephan.neuhaus@zhaw.ch&gt;
 * @author Bernhard Tellenbach &lt;tebe@zhaw.ch&gt;
 * @version 1.1
 * @date 2016-03-06
 */
public class Constants {
  /** The number of bits in a byte. */
  public static final int BITS_PER_BYTE = 8;

  /** Number of milliseconds in a second. */
  public static final long MILLIS_PER_SECOND = 1000L;

  /** Number of milliseconds in a nanosecond. */
  public static final long NANOS_PER_MILLI = 1000000L;

  /** Number of nanoseconds in a second. */
  public static final long NANOS_PER_SECOND = NANOS_PER_MILLI * MILLIS_PER_SECOND;

  /** Number of microseconds in a millisecond. */
  public static final long USECS_PER_MILLI = 1000L;

  /** Number of microseconds in a second. */
  public static final long USECS_PER_SECOND = USECS_PER_MILLI * MILLIS_PER_SECOND;

  /** Official name of the MD5 message digest algorithm. */
  public static final String MD5_DIGEST_NAME = "MD5";

  /** Number of seconds in a minute. */
  public static final long SECONDS_PER_MINUTE = 60;

  /** Number of seconds in a minute. */
  public static final long MINUTES_PER_HOUR = 60;

  /** Number of seconds in an hour. */
  public static final long SECONDS_PER_HOUR = SECONDS_PER_MINUTE * MINUTES_PER_HOUR;

}
