package ch.zhaw.sws2.random.bydate;

import java.time.ZonedDateTime;

/** A real system.
 *
 * <p>Provides actual system values, except for process IDs, for which there
 * is no portable way of doing it.</p>
 *
 * @author Stephan Neuhaus &lt;stephan.neuhaus@zhaw.ch&gt;
 * @author Bernhard Tellenbach &lt;tebe@zhaw.ch&gt;
 * @version 1.1
 * @date 2016-03-06
 */
public class MyRealSystemImpl implements MySystem {

  private int pid;
  private int ppid;

  /** Creates a real MySystem object (within reason).
   *
   * <p>Since there is no portable way of getting the process's PID or
   * parent process PID, we return the PIDs as given to us in the
   * constructor. Obviously, these values won't be correct any more
   * after forking.</p>
   *
   * @param pid this process's PID
   * @param ppid this process's parent PID
   */
  public MyRealSystemImpl(int pid, int ppid) {
    super();
    this.pid = pid;
    this.ppid = ppid;
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
    return ZonedDateTime.now().toEpochSecond();
  }

  @Override
  public int getUsecs() {
    return ZonedDateTime.now().getNano() / 1000;
  }

  @Override
  public ZonedDateTime getDateTime() {
    return null;
  }
}
