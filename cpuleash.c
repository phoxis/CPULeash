/*
**
**  CPULeash: Limits the utilization of the cpu by a process.
**  Author: Arjun Pakrashi [phoxis at gmail dot com]
**
**  This file is part of CPULeash.
**
**  CPULeash is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation, either version 3 of the License, or
**  (at your option) any later version.
**
**  CPULeash is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with CPULeash.  If not, see <http://www.gnu.org/licenses/>.
**  
*/

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
static void do_cleanup_pid (struct leash_pid_attrs *pid_attr, int n);
long int get_cpu_clk (FILE *fp);
double get_pid_cpu_util (pid_t pid, unsigned int flags, struct cpu_util_state *state);
static int leash_pid_attrs_compare (const void *a, const void *b);
void usage (void);

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
static void do_cleanup_pid (struct leash_pid_attrs *pid_attr, int n)
{
  int i;
  for (i=0; i<n; i++)
  {
    if (pid_attr[i].valid)
    {
      kill (pid_attr[i].pid, SIGCONT);
    }
  }
}


/* Non static functions */

void usage (void)
{
  int ncpus = get_cpu_cores ();
  
  fprintf (stdout, "CPULeash: Keeps a given running process leashed under a certain cpu utilization threshold\n");
  fprintf (stdout, "Usage:\ncpuleash (-l scaled_percent | -L absolute_percent) -p pid [-s sample_time] [-v] [-h]\n");
  fprintf (stdout, 
  "-l: Scaled percent value. Range [0, 100]. Target cpu value divided by the number of cpu \n\
    in the system. Current system: %d\n", ncpus);
  fprintf (stdout, 
  "-L: Absolute percent value. Range [0, %d]. Target cpu value is absolute.\n", 100 * ncpus);
  fprintf (stdout, "-p: PID to leash\n");
  fprintf (stdout, "-s: Sample time (optional)\n");
  fprintf (stdout, "-v: Verbose\n");
  fprintf (stdout, "-h: Shows this help\n");
  fprintf (stdout, "\nOption -p is mandatory. \n-l and -L are mutually exclusive and mandatory.\n");
  fprintf (stdout, "\nCPULeash version %s\nAuthor: Arjun Pakrashi (phoxis [at] gmail [dot] com)\n", VERSION);
}

struct leash_pid_attrs *malloc_leash_pid_attrs (int n)
{
  struct leash_pid_attrs *temp;
  int i;
  
  temp = malloc (sizeof (struct leash_pid_attrs) * n);
  if (temp == NULL)
  {
    return NULL;
  }
  
  for (i=0; i<n; i++)
  {
    temp[i].pid             = -1;
    temp[i].frac            = -1;
    temp[i].util            = -1;
    temp[i].dyn_ratio       = -1;
    temp[i].stop_time_nsec  = -1;
    temp[i].run_time_nsec   = -1;
    temp[i].valid           =  0;
    temp[i].util_state.iter =  0;
  }
  
  return temp;
}

void free_leash_pid_attrs (struct leash_pid_attrs *temp)
{
  free (temp);
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
double get_pid_cpu_util (pid_t pid, unsigned int flags, struct cpu_util_state *state)
{
  unsigned long int total_old_time, total_new_time, delta_time;
  double cpu_util = -1; /* NOTE: check for overflow */
//   double running_secs;
  long int uptime, idletime;
  int take_child_time_flag = 1, retval;
  FILE *uptime_fp = NULL, *pid_stat_fp;
  long int hz, nlcores;
  
  if (flags & LFLG_RESET_CPU_ITER)
  {
    state->iter = 0;
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
  if ((pid_stat_fp == NULL) && !is_pid_running (pid))
  {
    fprintf (stdout, "pid = %d is not running anymore\n", pid);
    return -2;
  }
  uptime_fp = open_uptime_file ();
  read_uptime_fields (uptime_fp, &uptime, &idletime);
  read_pid_stat_fields (pid_stat_fp, &state->new_pid_stat);
  retval = gettimeofday (&(state->this_time), NULL);
  if (retval != 0)
  {
    fprintf (stderr, "Problem calling \'gettimeofday\'\n");
    return cpu_util;
  }
  
  hz        = get_clk_tck_per_sec ();
  nlcores   = get_cpu_cores ();
  

  /* If this is the first time then just initialize */
  if (state->iter == 0)
  {
    state->old_pid_stat = state->new_pid_stat;
    state->last_time = state->this_time;
    state->iter++;
    return cpu_util;
  }

  total_new_time = state->new_pid_stat.utime + state->new_pid_stat.stime;
  total_old_time = state->old_pid_stat.utime + state->old_pid_stat.stime;

  if (take_child_time_flag)
  {
    total_new_time += state->new_pid_stat.cutime + state->new_pid_stat.cstime;
    total_old_time += state->old_pid_stat.cutime + state->old_pid_stat.cstime;
  }

  delta_time = (total_new_time - total_old_time);

//   running_secs = uptime - (new_pid_stat.starttime / (double) hz);
  cpu_util = 1.0 * (delta_time / ((double) hz * ((timeval_to_usec (state->this_time) - timeval_to_usec (state->last_time)) / (double) MICRO_MULT)));
  if (flags & LFLG_OVERALL_CPU_PERCENT)
  {
    cpu_util = cpu_util / (double) nlcores;
  }

  #if DEBUG==1
  printf ("old_utime: %lu, old_stime: %lu, old_cutime: %lu, old_cstime: %lu\n", 
          state->old_pid_stat.utime, state->old_pid_stat.stime, state->old_pid_stat.cutime, state->old_pid_stat.cstime);
  printf ("new_utime: %lu, new_stime: %lu, new_cutime: %lu, new_cstime: %lu\n",
          state->new_pid_stat.utime, state->new_pid_stat.stime, state->new_pid_stat.cutime, state->new_pid_stat.cstime);
  printf ("delta_time: %lu\n", delta_time);
  printf ("cpu_util: %lf%%\n", cpu_util);
  #endif

  state->old_pid_stat = state->new_pid_stat;
  state->last_time = state->this_time;
  state->iter++;
  
  close_uptime_file (uptime_fp);
  close_pid_stat (pid_stat_fp);
  
  return cpu_util;
}


static int leash_pid_attrs_compare (const void *a, const void *b)
{
  return ((struct leash_pid_attrs *) a)->stop_time_nsec - ((struct leash_pid_attrs *) b)->stop_time_nsec;
}
    
void leash_cpu (struct leash_pid_attrs *pid_attr, int n, struct timespec *user_sample_time, int flags)
{
  struct timespec stop_time, run_time;
  int count = 0, i;
  long int sample_nsec = SAMPLE_NSEC;
  long int *stop_segment, last_val;
  int valid_count;
  
  
  set_signal_handler (); /* TODO: Later restore the handler while cleanup */
  
  for (i=0, valid_count = 0; i<n; i++)
  {
    if (pid_attr[i].valid)
    {
      valid_count++;
    }
  }

  if ((flags & LFLG_SET_SAMPLE_TIME) && (user_sample_time != NULL))
  {
    #if DEBUG==1
    fprintf (stdout, "User specified sample time: %010ld\n", timespec_to_nsec (*user_sample_time));
    #endif
    /* NOTE: validate time format by user */
    sample_nsec = timespec_to_nsec (*user_sample_time);
  }
  
  for (i=0; i<n; i++)
  {
    if (pid_attr[i].valid)
    {
      pid_attr[i].dyn_ratio = pid_attr[i].frac;
      (void) get_pid_cpu_util (pid_attr[i].pid, LFLG_RESET_CPU_ITER, &pid_attr[i].util_state);
      pid_attr[i].util = pid_attr[i].frac;
    }
  }
  
  stop_segment = malloc (sizeof (long int) * n);
  if (stop_segment == NULL)
  {
    fprintf (stderr, "Not enough memory\n");
    return;
  }
  
  sigsetjmp (jmp_env, 1);
  while (!sig_flag)
  {
    for (i=0; i<n; i++)
    {
      if (pid_attr[i].valid)
      {
        pid_attr[i].dyn_ratio = pid_attr[i].dyn_ratio / pid_attr[i].util * pid_attr[i].frac;
        pid_attr[i].dyn_ratio = pid_attr[i].dyn_ratio > 1 ? 1 : pid_attr[i].dyn_ratio;
         
        pid_attr[i].run_time_nsec  = pid_attr[i].dyn_ratio * sample_nsec;
        pid_attr[i].stop_time_nsec = sample_nsec - pid_attr[i].run_time_nsec;
      }
    }
    
    if (flags & LFLG_VERBOSE)
    {
      /* NOTE: We can pass feedback function pointer. Or it is unnecessary */
      if (count % 24 == 0)
      {
        printf ("pid\ttarget\t\tcur_util\tdyn_ratio\tstop_time\trun_time\n");
      }
      for (i=0; i<n; i++)
      {
        if (pid_attr[i].valid)
        {
          printf ("%d\t%0.2f\t\t%0.2f\t\t%0.2f\t\t%010ld\t%010ld\n", pid_attr[i].pid, pid_attr[i].frac, pid_attr[i].util, pid_attr[i].dyn_ratio, pid_attr[i].stop_time_nsec, pid_attr[i].run_time_nsec);
        }
      }
      printf ("--\n");
    }
    
    /* Sort the 'pid_attr' in ascending order by stop_time_nsec. Then find the 'stop_segment'
     * timing after which the corresponding process should be started
     */
    qsort (pid_attr, n, sizeof (struct leash_pid_attrs), leash_pid_attrs_compare);
    for (i=0, last_val=0; i<n; i++)
    {
      if (pid_attr[i].valid)
      {
        stop_segment[i] = pid_attr[i].stop_time_nsec - last_val;
        last_val = pid_attr[i].stop_time_nsec;
      }
    }
    
    /* TODO: Check return value of kill and notify that the process has stopped */
    /* Stop all processes */
    for (i=0; i<n; i++)
    {
      if (pid_attr[i].valid)
      {
        kill (pid_attr[i].pid, SIGSTOP);
      }
    }
    
    /* Wake processes one by one in the order of stop_time_nsec, the amount of sleep is 
     * guided by the stop_segment
     */
    for (i=0; i<n; i++)
    {
      if (pid_attr[i].valid)
      {
        stop_time = nsec_to_timespec (stop_segment[i]);
        do_complete_nanosleep (stop_time);
        kill (pid_attr[i].pid, SIGCONT);
      }
    }
    
    /* Spend remaining sample time */
    for (i=n-1; i>=0; i--)
    {
      if (pid_attr[i].valid)
      {
        run_time = nsec_to_timespec(sample_nsec - pid_attr[n-1].run_time_nsec);
        break;
      }
    }
    do_complete_nanosleep (run_time);
    
    /* Get utilization for next iteration */
    for (i=0; i<n; i++)
    {
      if (pid_attr[i].valid)
      {
        pid_attr[i].util = get_pid_cpu_util (pid_attr[i].pid, LFLG_OVERALL_CPU_PERCENT, &pid_attr[i].util_state);
      }
      if (pid_attr[i].util == -2) /*TODO: make this process a bit better */
      {
        pid_attr[i].valid = 0;
        valid_count--;
        if (valid_count == 0)
        {
          raise (SIGINT);
        }
      }
    }
    
    count++;
  }
  
  /* Uncomment when we use this first time. This avoids the compiler warning */
//   LEASH_CLEANUP:
  
  free (stop_segment);
  do_cleanup_pid (pid_attr, n);
  
  return;
}


int main (int argc, char *argv[])
{
  char c, *optsrting = "l:L:vs:p:h", *endptr, *sep = ",", *tok;
  double *l_val, *L_val;
  long int nproc;
  double sample_sec = -1;
  int verbose = 0, i;
  unsigned int flags = 0x00, param_comb_invalid = 0, show_usage = 0;
  struct timespec user_sample_time;
  struct leash_pid_attrs *pid_attr;
  int pid_count = 0, l_val_count = 0, L_val_count = 0;
  int pid_temp;
  int l_val_alloc_size, L_val_alloc_size, pid_attr_alloc_size;
  
  /* TODO: resize as required */
  l_val_alloc_size = L_val_alloc_size = pid_attr_alloc_size = LMIN_PID_ATTR_N;
  
  pid_attr = malloc_leash_pid_attrs (pid_attr_alloc_size);
  l_val = malloc (sizeof (double) * l_val_alloc_size);
  L_val = malloc (sizeof (double) * L_val_alloc_size);
  
  for (i=0; i<l_val_alloc_size; i++)
  {
    l_val[i] = -1;
  }
  
  for (i=0; i<L_val_alloc_size; i++)
  {
    L_val[i] = -1;
  }
  
  while ((c = getopt (argc, argv, optsrting)) != -1)
  {
    switch (c)
    {
      case 'l':
        /* TODO: if l_val_count >= l_val_alloc_size then we need to resize */
        if (L_val_count != 0)
        {
          fprintf (stderr, "Options -l and -L are mutually exclusive\n");
          goto END_MAIN_CLEANUP;
        }
        
        tok = strtok (optarg, sep);
        do
        {
          l_val[l_val_count] = strtod (tok, &endptr);
          if (*endptr != '\0')
          {
            fprintf (stderr, "Malformed argument for -l: %s in %s\n", tok, optarg);
            goto END_MAIN_CLEANUP;
          }
          
          if ((l_val[l_val_count] < 0.0) || (l_val[l_val_count] > 100.0))
          {
            fprintf (stderr, "Invalid scaled leash value in -l: %lf in %s\nValid range is [0, 100]\n", l_val[l_val_count], optarg);
            goto END_MAIN_CLEANUP;
          }
          
          l_val_count++;
          tok = strtok (NULL, sep);
          
        } while (tok);
        
        break;
        
      case 'L':
        /* TODO: if L_val_count >= l_val_alloc_size then we need to resize */
        if (l_val_count != 0)
        {
          fprintf (stderr, "Options -l and -L are mutually exclusive\n");
          goto END_MAIN_CLEANUP;
        }
        
        tok = strtok (optarg, sep);
        do
        {
          L_val[L_val_count] = strtod (tok, &endptr);
          if (*endptr != '\0')
          {
            fprintf (stderr, "Malformed argument for -L: %s in %s\n", tok, optarg);
            goto END_MAIN_CLEANUP;
          }
        
          nproc = get_cpu_cores ();
          if ((L_val[L_val_count] < 0.0) || (L_val[L_val_count] > (nproc * 100.0)))
          {
            fprintf (stderr, "Invalid absolute leash value in -L: %lf in %s\nValid range is [0, %ld] in this system with %ld processors\n", L_val[L_val_count], optarg, nproc * 100, nproc);
            goto END_MAIN_CLEANUP;
          }
                    
          L_val_count++;
          tok = strtok (NULL, sep);
          
        } while (tok);
        
        break;
        
      case 's':
        sample_sec = strtod (optarg, &endptr);
        if (*endptr != '\0')
        {
          fprintf (stderr, "Malformed argument for -s: %s\n", optarg);
          goto END_MAIN_CLEANUP;
        }
        
        //TODO: Set an upper and lower limit
        if (sample_sec <= 0)
        {
          fprintf (stderr, "Invalid specified sample time: %lf\nSample time should be greater than 0 microseconds\n", sample_sec);
          goto END_MAIN_CLEANUP;
        }
        
        break;
        
      case 'p':
        /* TODO: if pid_count >= pid_attr_alloc_size then we need to resize */
        tok = strtok (optarg, sep);
        do
        {
          pid_temp = strtol (tok, &endptr, 10);
          if (*endptr != '\0')
          {
            fprintf (stderr, "Malformed argument for -p: %s\n", optarg);
            goto END_MAIN_CLEANUP;
          }
        
          if (pid_temp < 1)
          {
            fprintf (stderr, "Invalid pid specified in: %d in %s\n", pid_temp, optarg);
            goto END_MAIN_CLEANUP;
          }
          
          pid_attr[pid_count].pid = pid_temp;
          pid_attr[pid_count].valid = 1; /* FIXME: Set valid flag here ? */
          printf ("%s [[[%d]]\n", tok, pid_attr[pid_count].pid);
          pid_count++;
          tok = strtok (NULL, sep);
          
        } while (tok);
        
        break;
        
      case 'v':
        verbose = 1;
        break;
      
      case 'h':
        show_usage = 1;
        goto END_MAIN_CLEANUP;
        break;
        
      case ':':
        fprintf (stderr, "Option -%c requires an argument\n", optopt);
        break;
        
      case '?':
        fprintf (stderr, "Invalid option -%c\n", optopt);
        break;
        
      default:
        break;
    }
  }
  
  /* The vaues of L_val_count or l_val_count and pid_count should be same */
  
  /* Mandatory -l or -L and -p */
  if ((l_val_count == 0) && (L_val_count == 0))
  {
    fprintf (stderr, "Either -l or -L needs to be specified\n");
    param_comb_invalid = 1;
  }
  
  if (pid_count == 0)
  {
    fprintf (stderr, "Process ID needs to be specified using -p\n");
    param_comb_invalid = 1;
  }
  
  if ((l_val_count != 0) && (pid_count != l_val_count))
  {
    fprintf (stderr, "Number of arguments in -l and -p should be same\n");
    show_usage = 1;
    goto END_MAIN_CLEANUP;
  }
  else if ((L_val_count != 0) && (pid_count != L_val_count))
  {
    fprintf (stderr, "Number of arguments in -L and -p should be same\n");
    show_usage = 1;
    goto END_MAIN_CLEANUP;
  }
  
  if (param_comb_invalid)
  {
    show_usage = 1;
    goto END_MAIN_CLEANUP;
  }
  
 
  if (verbose) 
  {
    fprintf (stdout, "verbose =  %d\n", verbose);
    flags |= LFLG_VERBOSE;
  }
  
  /* Time is always manually set */
  if (sample_sec != -1)
  {
    user_sample_time = nsec_to_timespec ((long int) floor (sample_sec * NANO_MULT));
    if (verbose) fprintf (stdout, "Sample time: %lf sec\n(%ld sec, %ld nsec)\n", sample_sec, user_sample_time.tv_sec, user_sample_time.tv_nsec);
  }
  else
  {
    user_sample_time = nsec_to_timespec ((long int) SAMPLE_NSEC);
    if (verbose) fprintf (stdout, "Sample time (default): %ld us\n(%ld sec, %ld nsec)\n", (long int) SAMPLE_NSEC, user_sample_time.tv_sec, user_sample_time.tv_nsec);
  }
  flags |= LFLG_SET_SAMPLE_TIME;

  for (i=0; i<pid_count; i++)
  {    
    /* Parameter settings */
    if (l_val_count != 0)
    {
      pid_attr[i].frac = l_val[i] / 100.0;
      if (verbose) fprintf (stdout, "l = %lf\n", l_val[i]);
    }
  
    if (L_val_count != 0)
    {
      pid_attr[i].frac = L_val[i] / (100.0 * nproc);
      if (verbose) fprintf (stdout, "L = %lf\n", L_val[i]);
    }
    
    if (verbose) fprintf (stdout, "frac = %lf\n", pid_attr[i].frac);
    if (verbose) fprintf (stdout, "pid = %d\n", pid_attr[i].pid);
  
    if (verbose) fprintf (stdout, "\n");
  }

  for (i=0; i<pid_count; i++)
  {
    if (!is_pid_running (pid_attr[i].pid))
    {
      fprintf (stdout, "pid = %d is not running\n", pid_attr[i].pid);
      pid_attr[i].valid = 0;
    }
  }
  
  /* Call leash_cpu */
  leash_cpu (pid_attr, pid_count, &user_sample_time, flags);
  
  END_MAIN_CLEANUP:
  
  free_leash_pid_attrs (pid_attr);
  free (l_val);
  free (L_val);
  if (show_usage)
  {
    usage ();
  }
  
  return 0;
}
