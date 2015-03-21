// Challenges:
// Compute the amount of sleep required for each pid
// What should be the sample time within which the cpu utilization should be taken
//                        and the sample time is t. Then when we sleep in the loop for s seconds and then
//                        we again sleep for t seconds in the main loop making the sample interval s + t
//                        needs to be checked.
// TODO: See clock_nanosleep for better implementation possibility
// TODO: handle multi threaded application
// TODO: Handle process group capping
// TODO: Maybe thermal capping in future
// TODO: Deamonize
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <error.h>
#include <errno.h>

#define BUF_MAX 256
#define DEBUG 1

#define NANO_MULT 1000000000L

typedef struct _pid_stat_t {
  int pid;
  char comm[BUF_MAX];
  char state;
  int ppid;
  int pgrp;
  int session;
  int tty_nr;
  int tpgid;
  unsigned int flags;
  unsigned long int minflt;
  unsigned long int cminflt;
  unsigned long int majflt;
  unsigned long int cmajflt;
  unsigned long int utime;
  unsigned long int stime;
  unsigned long int cutime;
  unsigned long int cstime;
  unsigned long int priority;
  unsigned long int nice;
  unsigned long int num_threads;
  unsigned long int itrealvalue;
  unsigned long long int starttime;
  unsigned long int vsize;
  long int rss;
  unsigned long int rsslim;
  unsigned long int startcode;
  unsigned long int endcode;
  unsigned long int startstack;
  unsigned long int kstkesp;
  unsigned long int kstkeip;
  unsigned long int signal;
  unsigned long int blocked;
  unsigned long int sigignore;
  unsigned long int sigcatch;
  unsigned long int wchan;
  unsigned long int nswap;
  unsigned long int cnswap;
  int exit_signal;
  int processor;
  unsigned int rt_priority;
  unsigned int policy;
  unsigned long long int delayacct_blkio_ticks;
  unsigned long int guest_time;
  unsigned long int cguest_time;
} pid_stat_t;

void usage (void)
{
  printf ("Enter a pid and percentage to cap\n");
}

FILE *open_pid_stat (int pid)
{
  FILE *fp;
  char proc_path[256];
  sprintf (proc_path, "/proc/%d/stat", pid);
  fp = fopen (proc_path, "r");
  return fp;
}

void close_pid_stat (FILE *fp)
{
  fclose (fp);
}

int is_pid_running (int pid)
{
  DIR *dp;
  char proc_path[256];
  sprintf (proc_path, "/proc/%d/", pid);

  dp = opendir (proc_path);
  if (dp == NULL)
  {
    return 0;
  }
  else
  {
    closedir (dp);
  }
  return 1;
}

void handler_sigint (int signal)
{
  return;
}

int set_signal_handler (void)
{
  struct sigaction sa;
  int retval;

  sigemptyset (&sa.sa_mask); 
  sa.sa_flags = 0;
  sa.sa_handler = handler_sigint;
  retval = sigaction (SIGINT, &sa, NULL);
  if (retval == -1)
  {
    error (0, errno, __func__);
  }
  return retval;
}

int do_complete_nanosleep (struct timespec sleeptime)
{
  struct timespec treq, tret;
  int retval = 0;

  treq = sleeptime;  

  #ifdef DEBUG
  printf ("nanosleeping %d sec, %ld nanosec\n", (int) sleeptime.tv_sec, sleeptime.tv_nsec);
  #endif

  do
  {
    retval = nanosleep (&treq, &tret);
    if (retval == -1)
    {
      if (errno == EINTR)
      {
        #ifdef DEBUG
        printf ("[%d %ld], [%d %ld]\n", (int) treq.tv_sec, (long int) treq.tv_nsec, (int) tret.tv_sec, (long int) tret.tv_nsec);
        #endif
      }
      else
      {
        break;
      }
    }
    else if (retval == 0)
    {
      break;
    }
    treq = tret; 
  } while (1);

  return retval;  
}

/* Get fields, 14, 15, 16, 17 here. We need to call flush in this
 * function or before calling in order to read the updated values
 */
int read_pid_stat_fields (FILE *fp, pid_stat_t *stat_struct)
{
  char buffer[BUF_MAX];

  fflush (fp);
  fseek (fp, 0, SEEK_SET);
  if (!fgets (buffer, BUF_MAX, fp))
  { perror ("Error"); }

  sscanf (buffer, "%d %s %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld \
                   %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu \
                   %lu %lu %lu %d %d %u %u %llu %lu %ld", 
                   &stat_struct->pid, stat_struct->comm, &stat_struct->state, &stat_struct->ppid, &stat_struct->pgrp,
                   &stat_struct->session, &stat_struct->tty_nr, &stat_struct->tpgid, &stat_struct->flags, &stat_struct->minflt,
                   &stat_struct->cminflt, &stat_struct->majflt, &stat_struct->cmajflt, &stat_struct->utime, &stat_struct->stime,
                   &stat_struct->cutime, &stat_struct->cstime, &stat_struct->priority, &stat_struct->nice, &stat_struct->num_threads,
                   &stat_struct->itrealvalue, &stat_struct->starttime, &stat_struct->vsize, &stat_struct->rss, &stat_struct->rsslim,
                   &stat_struct->startcode, &stat_struct->endcode, &stat_struct->startstack, &stat_struct->kstkesp, &stat_struct->kstkeip,
                   &stat_struct->signal, &stat_struct->blocked, &stat_struct->sigignore, &stat_struct->sigcatch, &stat_struct->wchan,
                   &stat_struct->nswap, &stat_struct->cnswap, &stat_struct->exit_signal, &stat_struct->processor, &stat_struct->rt_priority,
                   &stat_struct->policy, &stat_struct->delayacct_blkio_ticks, &stat_struct->guest_time, &stat_struct->cguest_time
         );
             

  return 1;
}

FILE *open_uptime_file (void)
{
  FILE *fp = fopen ("/proc/uptime", "r");
  return fp;
}

void close_uptime_file (FILE *fp)
{
  fclose (fp);
}

void read_uptime_fields (FILE *fp, long int *uptime, long int *idle)
{
  fflush (fp);
  fseek (fp, 0, SEEK_SET);
  fscanf (fp, "%ld %ld", uptime, idle);
  return;
}

#ifdef DEBUG
void read_pid_stats_test (int pid)
{
  FILE *fp;
  pid_stat_t stat_struct;

  fp = open_pid_stat (pid);
  read_pid_stat_fields (fp, &stat_struct);
  printf ("%d %s %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld \
           %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu \
           %lu %lu %lu %d %d %u %u %llu %lu %ld\n",
           stat_struct.pid, stat_struct.comm, stat_struct.state, stat_struct.ppid, stat_struct.pgrp,
           stat_struct.session, stat_struct.tty_nr, stat_struct.tpgid, stat_struct.flags, stat_struct.minflt,
           stat_struct.cminflt, stat_struct.majflt, stat_struct.cmajflt, stat_struct.utime, stat_struct.stime,
           stat_struct.cutime, stat_struct.cstime, stat_struct.priority, stat_struct.nice, stat_struct.num_threads,
           stat_struct.itrealvalue, stat_struct.starttime, stat_struct.vsize, stat_struct.rss, stat_struct.rsslim,
           stat_struct.startcode, stat_struct.endcode, stat_struct.startstack, stat_struct.kstkesp, stat_struct.kstkeip,
           stat_struct.signal, stat_struct.blocked, stat_struct.sigignore, stat_struct.sigcatch, stat_struct.wchan,
           stat_struct.nswap, stat_struct.cnswap, stat_struct.exit_signal, stat_struct.processor, stat_struct.rt_priority,
           stat_struct.policy, stat_struct.delayacct_blkio_ticks, stat_struct.guest_time, stat_struct.cguest_time
         );
  close_pid_stat (fp);
}
#endif

long get_clk_tck_per_sec (void)
{
  return sysconf (_SC_CLK_TCK);
}


struct timespec nsec_to_timespec (long int nsec)
{
  struct timespec temp;

  temp.tv_nsec = nsec % NANO_MULT;
  temp.tv_sec  = nsec / NANO_MULT;

  return temp;
}

long int timespec_to_nsec (struct timespec temp)
{
  return temp.tv_sec * NANO_MULT + temp.tv_nsec;
}


#define SAMPLE_NSEC (1 * NANO_MULT)
/* NOTE: WORKS IN SINGLE THREADED APPLICATION */
void leash_cpu (int pid, double percent)
{
  int take_child_flag = 0, stop_flag = 0;
  pid_stat_t new_pid_stat, old_pid_stat;
  FILE *fp;
  long int old_util, new_util, delta_util, adjustment, target_clk_delta, hz, adjustment_stop_time, temp, target_nsec;
  struct timespec stop_time, stop_time_base, remaining_sleep_time, sample_time;
  
  hz = get_clk_tck_per_sec ();
  
  stop_flag = 0;

  sample_time = nsec_to_timespec (SAMPLE_NSEC);
  
  target_nsec      = (long int) ((percent / 100.0) * timespec_to_nsec (sample_time));
  target_clk_delta = (long int) ceill ((target_nsec / (long double) NANO_MULT) * hz);
  stop_time        = nsec_to_timespec (timespec_to_nsec (sample_time) - target_nsec);

  stop_time_base = stop_time;

  fp = open_pid_stat (pid);
  while (1)
  {
    /* Get current clock ticks */
    read_pid_stat_fields (fp, &old_pid_stat);
    old_util = old_pid_stat.utime + old_pid_stat.stime;
    if (take_child_flag == 1)
    {
      old_util += old_pid_stat.cutime + old_pid_stat.cstime;
    }

    
    if (stop_flag)
    {
      #ifdef DEBUG
      printf ("Stopping pid = %d\n", pid);
      #endif
      /* Stop the process for desired seconds */
      kill (pid, SIGSTOP);
      do_complete_nanosleep (stop_time);
      kill (pid, SIGCONT);

      /* Compute the remaining time within the sample range */
      remaining_sleep_time = nsec_to_timespec (timespec_to_nsec (sample_time) - timespec_to_nsec (stop_time));
    }
    else
    {    
      /* Compute the remaining time within the sample range */
      do_complete_nanosleep (stop_time);
      remaining_sleep_time = nsec_to_timespec (timespec_to_nsec (sample_time) - timespec_to_nsec (stop_time));
    }
    

    #ifdef DEBUG
    printf ("Sleeping remainder of sample interval\n");
    printf ("sample_time.tv_sec = %d, sample_time.tv_nsec = %ld, stop_time.tv_sec = %d, stop_time.tv_nsec = %ld, remaining_sleep_time.tv_sec = %d, remaining_sleep_time.tv_nsec = %d\n", sample_time.tv_sec, sample_time.tv_nsec, stop_time.tv_sec, stop_time.tv_nsec, remaining_sleep_time.tv_sec, remaining_sleep_time.tv_nsec);
    #endif

    /* Sleep the remaining time to complete the sample interval */
    do_complete_nanosleep (remaining_sleep_time);
    
    
    /* Get current clock ticks */
    read_pid_stat_fields (fp, &new_pid_stat);
    new_util = new_pid_stat.utime + new_pid_stat.stime;
    if (take_child_flag == 1)
    {
      new_util += new_pid_stat.cutime + new_pid_stat.cstime;
    }
    
    delta_util           = new_util - old_util;
    adjustment           = target_clk_delta - delta_util;
    adjustment_stop_time = labs ((adjustment / (double) hz) * NANO_MULT); // target_clk_delta and delta_util is already scaled to sample_time

    #ifdef DEBUG
    printf ("ADJUST: %ld, clk = %ld\n", adjustment_stop_time, adjustment);  
    printf ("delta_util = %ld, target_clk_delta = %ld\n", delta_util, target_clk_delta);
    #endif

    if (adjustment >= 0)
    {
      stop_flag = 1;
      stop_time = nsec_to_timespec (timespec_to_nsec (stop_time_base) - adjustment_stop_time);
      #ifdef DEBUG
      printf ("--\n");
      #endif
    }
    else
    {
      stop_flag = 1;
      stop_time = nsec_to_timespec (timespec_to_nsec (stop_time_base) + adjustment_stop_time);
      #ifdef DEBUG
      printf ("++\n");
      #endif
    }
    // NOTE: Make sure timing does not overflow the sample time and does not underflow the 0 mark
    printf ("stop_time.tv_sec = %d, stop_time.tv_nsec = %ld\n", stop_time.tv_sec, stop_time.tv_nsec);
  }
  
  close_pid_stat (fp);
}
 


/* WARNING: TEST FUNCTION */
void get_pid_cpu_util (FILE *fp)
{
  static int iter = 0;
  static pid_stat_t old_pid_stat, new_pid_stat;
  unsigned long int total_old_time, total_new_time, delta_time;
  double cpu_util = -1, running_secs; /* TODO: check for overflow */
  long int uptime, idletime;
  int take_child_time_flag = 1, sample_time_sec = 2; /* TODO: This needs to be in centralized configuration */
  FILE *uptime_fp;
  long int hz;
  struct timespec sample_time;
  sample_time.tv_sec = sample_time_sec;
  sample_time.tv_nsec = 0;


  
  fflush (fp);
  read_pid_stat_fields (fp, &new_pid_stat);
  if (iter == 0)
  {
    old_pid_stat = new_pid_stat;
    do_complete_nanosleep (sample_time); /* Need to make this sleep configurable */
    fflush (fp);
    read_pid_stat_fields (fp, &new_pid_stat);
  }

  total_new_time = new_pid_stat.utime + new_pid_stat.stime;
  total_old_time = old_pid_stat.utime + old_pid_stat.stime;

  if (take_child_time_flag)
  {
    total_new_time += new_pid_stat.cutime + new_pid_stat.cstime;
    total_old_time += old_pid_stat.cutime + old_pid_stat.cstime;
  }

  delta_time = (total_new_time - total_old_time);

  hz = get_clk_tck_per_sec ();
  uptime_fp = open_uptime_file ();
  read_uptime_fields (uptime_fp, &uptime, &idletime);
  
  // FIXME: Here we need to know after how long this function was again called in the
  // context of one specific pid. Else we need some other way to get the cpu utilization
  // We do not want to divide it with sample_time_sec
  running_secs = uptime - (new_pid_stat.starttime / (double) hz);
//  cpu_util = 100.0 * ((total_new_time / (double) hz) / running_secs);
  cpu_util = 100.0 * (delta_time / ((double) hz * sample_time_sec));

  #ifdef DEBUG
  printf ("old_utime: %lu, old_stime: %lu, old_cutime: %lu, old_cstime: %lu\n", 
          old_pid_stat.utime, old_pid_stat.stime, old_pid_stat.cutime, old_pid_stat.cstime);
  printf ("new_utime: %lu, new_stime: %lu, new_cutime: %lu, new_cstime: %lu\n",
          new_pid_stat.utime, new_pid_stat.stime, new_pid_stat.cutime, new_pid_stat.cstime);
  printf ("delta_time: %lu\n", delta_time);
  printf ("cpu_util: %lf%%\n", cpu_util);
  #endif

  old_pid_stat = new_pid_stat;
  iter++;
}

int main (int argc, char *argv[])
{
  int pid;
  double percent;

  if (argc <  2)
  {
    usage ();
    exit (0);
  }

  pid = atoi (argv[1]);
  percent = atof (argv[2]);

  FILE *fp = open_pid_stat (pid);
  get_pid_cpu_util (fp);
  sleep (1);
  get_pid_cpu_util (fp);

  if (!is_pid_running (pid))
  {
    printf ("PID = %d is not running\n", pid);
    exit (0);
  }
  set_signal_handler ();
leash_cpu (pid, percent);
/*
  printf ("Sending SIGSTOP to PID = %d\n", pid);
  kill (pid, SIGSTOP);
  printf ("Sleeping for 5 seconds\n");
  do_complete_nanosleep (5,5000);
  printf ("Sending SIGCONT to PID = %d\n", pid);
  kill (pid, SIGCONT);
*/
  return 0;
}

