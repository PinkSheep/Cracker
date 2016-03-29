package ch.zhaw.sws2.random.bydate;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;

/** A faked system.
 *
 * <p>Fakes time-of-day and process IDs through constructor parameters.</p>
 *
 * @author Stephan Neuhaus &lt;stephan.neuhaus@zhaw.ch&gt;
 * @author Bernhard Tellenbach &lt;tebe@zhaw.ch&gt;
 * @version 1.1
 * @date 2016-03-06
 */
public class MyFakeSystemImpl implements MySystem {
  private int pid;
  private int ppid;
  private long microSecondsSinceEpoch;
  private ZoneId zone;


  /**
   * Creates a MySystem object with a specified Epoch date/time 
   * (in microseconds), PID, and PPID.
   */
  public MyFakeSystemImpl(long microsecondsSinceEpoch, ZoneId zone) {
    super();
    this.pid = 0;
    this.ppid = 0;
    this.microSecondsSinceEpoch = microsecondsSinceEpoch;
    this.zone = zone;
  }

  @Override
  public int getpid() {
    return pid;
  }

  @Override
  public int getppid() {
    return ppid;
  }

  @Override
  public long getSecondsSinceEpoch() {
    return microSecondsSinceEpoch / Constants.USECS_PER_SECOND;
  }

  @Override
  public int getUsecs() {
    return (int)(microSecondsSinceEpoch % Constants.USECS_PER_SECOND);
  }

  @Override
  public ZonedDateTime getDateTime() {
    Instant i = Instant.ofEpochSecond( getSecondsSinceEpoch() );
    return ZonedDateTime.ofInstant( i, zone );
  }
  
  /**
   * Add the supplied number of microseconds to the 
   * current time value.  
   * 
   * @param increment increment in microseconds
   */
  public void addMicroseconds(long microseconds) {
    microSecondsSinceEpoch += microseconds;
  }
  
}
