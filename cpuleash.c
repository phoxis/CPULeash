#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <setjmp.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <error.h>
#include <errno.h>
#include <limits.h>

#include "cpuleash.h"

static FILE *open_pid_stat (int pid);
static void close_pid_stat (FILE *fp);
static void handler_sigint (int signal);
static int set_signal_handler (void);
static int do_complete_nanosleep (struct timespec sleeptime);
static int read_pid_stat_fields (FILE *fp, pid_stat_t *stat_struct);
static FILE *open_uptime_file (void);
static void close_uptime_file (FILE *fp);
static void read_uptime_fields (FILE *fp, long int *uptime, long int *idle);
// static void read_pid_stats_test (int pid);
// static long int get_cpu_clk (FILE *fp);
static void do_cleanup (pid_t pid);
long int get_cpu_clk (FILE *fp);
double get_pid_cpu_util (pid_t pid, unsigned int flags);


static volatile sig_atomic_t sig_flag = 0;
static sigjmp_buf jmp_env;

/* Static functions */

static FILE *open_pid_stat (int pid)
{
  FILE *fp;
  char proc_path[PATH_MAX];
  sprintf (proc_path, "/proc/%d/stat", pid);
  fp = fopen (proc_path, "r");
  return fp;
}

static void close_pid_stat (FILE *fp)
{
  fclose (fp);
}

int is_pid_running (int pid)
{
  DIR *dp;
  char proc_path[PATH_MAX];
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

static void handler_sigint (int signal)
{
  if (signal == SIGINT)
  {
    sig_flag = 1;
    siglongjmp (jmp_env, 1);
  }
  return;
}

static int set_signal_handler (void)
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

static int do_complete_nanosleep (struct timespec sleeptime)
{
  struct timespec treq, tret;
  int retval = 0;

  treq = sleeptime;  

  #if DEBUG==1
  fprintf (stdout, "nanosleeping %d sec, %ld nanosec\n", (int) sleeptime.tv_sec, sleeptime.tv_nsec);
  #endif

  do
  {
    retval = nanosleep (&treq, &tret);
    if (retval == -1)
    {
      switch (errno)
      {
        case EINTR:
          #if DEBUG==1
          error (0, errno, "Request: [%d %ld], Remain: [%d %ld]\n", (int) treq.tv_sec, (long int) treq.tv_nsec, (int) tret.tv_sec, (long int) tret.tv_nsec);
          #endif
          break;
          
        case EFAULT:
          #if DEBUG==1
          error (0, errno, "Request: [%d %ld], Remain: [%d %ld]\n", (int) treq.tv_sec, (long int) treq.tv_nsec, (int) tret.tv_sec, (long int) tret.tv_nsec);
          #endif
          goto DO_COMPLETE_NANOSLEEP_OUT;
          break;
          
        case EINVAL:
          #if DEBUG==1
          error (0, errno, "Request: [%d %ld], Remain: [%d %ld]\n", (int) treq.tv_sec, (long int) treq.tv_nsec, (int) tret.tv_sec, (long int) tret.tv_nsec);
          #endif
          goto DO_COMPLETE_NANOSLEEP_OUT;
          break;
      }
    }
    treq = tret; 
  } while (retval == -1);

  DO_COMPLETE_NANOSLEEP_OUT:
  
  return retval;  
}

/* Get fields, 14, 15, 16, 17 here. We need to call flush in this
 * function or before calling in order to read the updated values
 */
static int read_pid_stat_fields (FILE *fp, pid_stat_t *stat_struct)
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

static FILE *open_uptime_file (void)
{
  FILE *fp = fopen ("/proc/uptime", "r");
  return fp;
}

static void close_uptime_file (FILE *fp)
{
  fclose (fp);
}

static void read_uptime_fields (FILE *fp, long int *uptime, long int *idle)
{
  fflush (fp);
  fseek (fp, 0, SEEK_SET);
  fscanf (fp, "%ld %ld", uptime, idle);
  return;
}


/* TEST */
/*
static void read_pid_stats_test (int pid)
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
*/

/*
static long int get_cpu_clk (FILE *fp)
{
  pid_stat_t pid_stat;
  long int util = 0;
  int take_child_flag = 0; // NOTE: Need to make configurable
  
  read_pid_stat_fields (fp, &pid_stat);
  util = pid_stat.utime + pid_stat.stime;
  if (take_child_flag == 1)
  {
    util += pid_stat.cutime + pid_stat.cstime;
  }
  
  return util;
}
*/

/* Sent SIGCONT to pid. This is done before exitting */
static void do_cleanup (pid_t pid)
{
  kill (pid, SIGCONT);
}


/* Non static functions */

void usage (void)
{
  printf ("Enter a pid and percentage to cap\n");
}

long get_clk_tck_per_sec (void)
{
  return sysconf (_SC_CLK_TCK);
}

/* NOTE: Returning number of online cpus. Not the number of configures cpus */
long get_cpu_cores (void)
{
  return sysconf (_SC_NPROCESSORS_ONLN);
  /*sysconf (_SC_NPROCESSORS_CONF); */
}

/* Convert nano seconds to struct timespec */
struct timespec nsec_to_timespec (long int nsec)
{
  struct timespec temp;

  temp.tv_nsec = nsec % NANO_MULT;
  temp.tv_sec  = nsec / NANO_MULT;

  return temp;
}

/* Convert struct timespec to nano seconds */
long int timespec_to_nsec (struct timespec temp)
{
  return temp.tv_sec * NANO_MULT + temp.tv_nsec;
}


/* Convert micro seconds to struct timeval */
struct timeval usec_to_timeval (long int usec)
{
  struct timeval temp;
  
  temp.tv_usec = usec % MICRO_MULT;
  temp.tv_sec  = usec / MICRO_MULT;
  
  return temp;
}

/* Convert timeval to micro seconds */
long int timeval_to_usec (struct timeval temp)
{
  return temp.tv_sec * MICRO_MULT + temp.tv_usec;
}


/* On first call or when flags is set to LFLG_RESET_CPU_ITER this function
 * will return -1. This function is a utility to use in other functions
 */
double get_pid_cpu_util (pid_t pid, unsigned int flags)
{
  static int iter = 0;
  static struct timeval last_time, this_time;
  static pid_stat_t old_pid_stat, new_pid_stat;
  unsigned long int total_old_time, total_new_time, delta_time;
  double cpu_util = -1; /* NOTE: check for overflow */
//   double running_secs;
  long int uptime, idletime;
  int take_child_time_flag = 1, retval;
  FILE *uptime_fp = NULL, *pid_stat_fp;
  long int hz, nlcores;
  
  if (flags & LFLG_RESET_CPU_ITER)
  {
    iter = 0;
  }
  
  /* NOTE:
   * Shall we get the file pointers and then hold them, or open-close
   * them at each call. Anyways this function is not re-entrant. One problem
   * holding the file pointers will be, how to free them. The closing
   * responsibility then needs to go to the caller or a special flag 
   * telling to close it, or just ignore closing.
   * Check the impact of openning and closing at each call.
   */
  pid_stat_fp = open_pid_stat (pid);
  uptime_fp = open_uptime_file ();
  read_uptime_fields (uptime_fp, &uptime, &idletime);
  read_pid_stat_fields (pid_stat_fp, &new_pid_stat);
  retval = gettimeofday (&this_time, NULL);
  if (retval != 0)
  {
    fprintf (stderr, "Problem calling \'gettimeofday\'\n");
    return cpu_util;
  }
  
  hz        = get_clk_tck_per_sec ();
  nlcores   = get_cpu_cores ();
  

  /* If this is the first time then just initialize */
  if (iter == 0)
  {
    old_pid_stat = new_pid_stat;
    last_time = this_time;
    iter++;
    return cpu_util;
  }

  total_new_time = new_pid_stat.utime + new_pid_stat.stime;
  total_old_time = old_pid_stat.utime + old_pid_stat.stime;

  if (take_child_time_flag)
  {
    total_new_time += new_pid_stat.cutime + new_pid_stat.cstime;
    total_old_time += old_pid_stat.cutime + old_pid_stat.cstime;
  }

  delta_time = (total_new_time - total_old_time);

//   running_secs = uptime - (new_pid_stat.starttime / (double) hz);
  cpu_util = 1.0 * (delta_time / ((double) hz * ((timeval_to_usec (this_time) - timeval_to_usec (last_time)) / (double) MICRO_MULT)));
  if (flags & LFLG_OVERALL_CPU_PERCENT)
  {
    cpu_util = cpu_util / (double) nlcores;
  }

  #if DEBUG==1
  printf ("old_utime: %lu, old_stime: %lu, old_cutime: %lu, old_cstime: %lu\n", 
          old_pid_stat.utime, old_pid_stat.stime, old_pid_stat.cutime, old_pid_stat.cstime);
  printf ("new_utime: %lu, new_stime: %lu, new_cutime: %lu, new_cstime: %lu\n",
          new_pid_stat.utime, new_pid_stat.stime, new_pid_stat.cutime, new_pid_stat.cstime);
  printf ("delta_time: %lu\n", delta_time);
  printf ("cpu_util: %lf%%\n", cpu_util);
  #endif

  old_pid_stat = new_pid_stat;
  last_time  = this_time;
  iter++;
  
  close_uptime_file (uptime_fp);
  close_pid_stat (pid_stat_fp);
  
  return cpu_util;
}

void leash_cpu (int pid, double frac, struct timespec *user_sample_time, int flags)
{
  double util, dyn_ratio;
  long int stop_time_nsec, run_time_nsec;
  struct timespec stop_time, run_time;
  int count = 0;
  long int sample_nsec = SAMPLE_NSEC;
  
  if ((flags & LFLG_SET_SAMPLE_TIME) && (user_sample_time != NULL))
  {
    #if DEBUG==1
    fprintf (stdout, "User specified sample time: %010ld\n", timespec_to_nsec (*user_sample_time));
    #endif
    sample_nsec = timespec_to_nsec (*user_sample_time);
  }
    
  dyn_ratio = frac;
  (void) get_pid_cpu_util (pid, LFLG_RESET_CPU_ITER);
  util = frac;
  while (1)
  {
    dyn_ratio = dyn_ratio / util * frac;
    dyn_ratio = dyn_ratio > 1 ? 1 : dyn_ratio;
    
    run_time_nsec = dyn_ratio * sample_nsec;
    stop_time_nsec  = sample_nsec - run_time_nsec;
    
    stop_time = nsec_to_timespec (stop_time_nsec);
    run_time = nsec_to_timespec (run_time_nsec);
    
    if (flags & LFLG_VERBOSE)
    {
      if (count % 24 == 0)
      {
        printf ("frac\tutil\tdyn_ratio\t\tstop\t\trun\n");
      }
      printf ("%0.2f\t%0.2f\t%0.2f\t\t%010ld\t\t%010ld\n", frac, util, dyn_ratio, stop_time_nsec, run_time_nsec);
    }
    
    if (stop_time_nsec > 0)
    {
      // TODO: Check if tht pid exists
      kill (pid, SIGSTOP);
      do_complete_nanosleep (stop_time);
      kill (pid, SIGCONT);
    }
    do_complete_nanosleep (run_time);
    
    
    util = get_pid_cpu_util (pid, LFLG_OVERALL_CPU_PERCENT);
    count++;
  }
}

int main (int argc, char *argv[])
{
  int pid, overall_percent_flag;
  double percent, frac;
  unsigned int flags = 0x00;
  struct timespec user_sample_time;

  if (argc <  3)
  {
    usage ();
    exit (0);
  }

  pid = atoi (argv[1]);
  percent = atof (argv[2]);
  if (argc == 4)
  {
    overall_percent_flag = atoi (argv[3]);
    overall_percent_flag = (overall_percent_flag != 0); /* 0 or 1 */
  }
  else
  {
    overall_percent_flag = 1;
  }

  if (overall_percent_flag == 1)
  {
    flags |= LFLG_OVERALL_CPU_PERCENT;
  }
  flags |= (LFLG_VERBOSE | LFLG_SET_SAMPLE_TIME);
  user_sample_time = nsec_to_timespec (SAMPLE_NSEC/2.0);
  
  if (!is_pid_running (pid))
  {
    printf ("PID = %d is not running\n", pid);
    exit (0);
  }
  
  set_signal_handler ();
  
  frac = percent / 100.0;
  
  sigsetjmp (jmp_env, 1);
  if (!sig_flag)
  {
    leash_cpu (pid, frac, &user_sample_time, flags);
  }
  else
  {
    do_cleanup (pid);
  }

  return 0;
}

