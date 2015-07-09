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

#ifndef CPULEASH_H
#define CPULEASH_H

#include "list.h"

#define VERSION "1.0"

#define BUF_MAX 256
#define LMIN_PID_ATTR_N 16
#define MAX_PIDS 32768
#define GRP_TOLERANCE (0.01)
// #define DEBUG 1

#define NANO_MULT  1000000000L
#define MICRO_MULT 1000000L

#define LFLG_OVERALL_CPU_PERCENT 0x01
#define LFLG_RESET_CPU_ITER      0x02
#define LFLG_SET_SAMPLE_TIME     0x04
#define LFLG_VERBOSE             0x08
#define LFLG_GROUP               0x10

#define SAMPLE_NSEC (1.0 * NANO_MULT)
#define SAMPLE_USEC (1.0 * MICRO_MULT)

#define SET(bitmap,x) (bitmap[(x)>>3] |= (0x01 << ((x) & 0x07)))
#define CLEAR(bitmap,x) (bitmap[(x)>>3] &= ~(0x01 << ((x) & 0x07)))
#define IS_SET(bitmap,x) (bitmap[(x)>>3] & (0x01 << ((x) & 0x07)))


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


struct cpu_util_state
{
  int iter;
  struct timeval last_time, this_time;
  pid_stat_t old_pid_stat, new_pid_stat;  
};

struct leash_pid_attrs
{
  pid_t pid;
  double frac, dyn_frac, util, dyn_ratio;
  long int stop_time_nsec, run_time_nsec;
  struct cpu_util_state util_state;
  struct list_head pid_link;
  int valid;
};

struct leash_pid_attrs *malloc_leash_pid_attrs (void);
void free_leash_pid_attrs (struct leash_pid_attrs *ptr);

void usage (void);
long get_clk_tck_per_sec (void);
long get_cpu_cores (void);
struct timespec nsec_to_timespec (long int nsec);
long int timespec_to_nsec (struct timespec temp);
struct timeval usec_to_timeval (long int usec);
long int timeval_to_usec (struct timeval temp);
int is_pid_running (int pid);
void leash_cpu (struct list_head *pid_attr_list_head, double group_leash_value, int n, struct timespec *user_sample_time, int flags);
 


#endif
