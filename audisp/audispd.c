/* audispd.c -- 
 * Copyright 2007 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 * Typist:
 *   James Antill <jantill@redhat.com>
 *
 *  The main design constraint on this implementation was lines of code: 
 * efficiency of the CPU and memory, future features and
 * reliability/maintainability were all sacrificed for this goal.
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <poll.h>
#include <sys/time.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/wait.h>

#include "libaudit.h"

#ifndef CONF_AF_LOCAL_PATH
#define CONF_AF_LOCAL_PATH "/var/run/audit_events"
#endif

#ifndef CONF_CHDIR_PATH
#define CONF_CHDIR_PATH "/"
#endif

#define CONF_SYSLOG_PRIO LOG_DAEMON

#define CONF_CON_OUT_SZ   32 /* max buffered messages */
#define CONF_CON_NUM_SZ   32 /* max number of connections -- Note 0,1,2 incl. */

#define TRUE  1
#define FALSE 0

struct auditd_msg
{
 struct audit_dispatcher_header hdr;
 char msg[MAX_AUDIT_MESSAGE_LENGTH];
};

struct con_data
{
 struct auditd_msg out[CONF_CON_OUT_SZ];
 size_t num; /* number of out[] that have been used atm. */
 size_t off; /* number of out[] that we've sent out the socket.
                always < num, or zero */
 size_t used; /* amount of current message used.
                 always < sizeof(auditd_msg) */

 unsigned int active : 1;
};

static void die(const char *, ...) __attribute__ ((format (printf, 1, 2)));
static void die(const char *msg, ...)
{
  va_list va;

  va_start(va, msg);
  vsyslog(LOG_ERR, msg, va);
  va_end(va);
  
  abort();
}

void io__set_nonblock(int fd)
{
  int flags = 0;

  if ((flags = fcntl(fd, F_GETFL)) == -1)
    die("%s: fcntl(F_GETFL): %m", __func__);
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    die("%s: fcntl(F_SETFL): %m", __func__);
}

static struct pollfd st_poll__fds[CONF_CON_NUM_SZ + 1];
static const size_t st_poll__max = CONF_CON_NUM_SZ;

static void io_poll_init(void)
{
  unsigned int scan = 0;

  while (scan < CONF_CON_NUM_SZ)
    st_poll__fds[scan++].fd = -1;
}

static void io_poll_add(int fd, int events)
{
  io__set_nonblock(fd);
  
  st_poll__fds[fd].events  = events;
  st_poll__fds[fd].revents = 0;
  st_poll__fds[fd].fd      = fd;
}

static void io_poll_del(int fd)
{
  st_poll__fds[fd].fd = -1;
}

static void io_poll_block(void)
{
  while (poll(st_poll__fds, st_poll__max + 1, -1) == -1)
    if ((errno != EAGAIN) && (errno != EINTR))
      die("poll: %m");
}

static ssize_t read_all(int fd, void *buf, size_t len, int force_block)
{
  size_t got = 0;

  while (got != len)
  {
    ssize_t tmp = read(fd, buf + got, len - got);

    if ((tmp == -1) && (errno == EAGAIN) && (got || force_block))
    {
      poll(st_poll__fds + fd, 1, -1);
      continue;
    }
    if ((tmp == -1) || !tmp)
      return (tmp);
    
    got += (size_t)tmp;
  }
  
  return (got);
}

static struct con_data con_data[CONF_CON_NUM_SZ + 1];

static void con_init(void)
{
  unsigned int scan = 0;

  while (scan < CONF_CON_NUM_SZ)
    con_data[scan++].active = FALSE;
}

static size_t con_data_used_num(const struct con_data *con)
{
  return (con->num - con->off);
}

static void con_data_add(struct con_data *con, const struct auditd_msg *aud)
{
  if (con->num == CONF_CON_OUT_SZ)
  {
    memmove(con->out, con->out + con->off, con->num * sizeof(con->out[0]));
    con->num -= con->off;
    con->off = 0;
  }
  
  con->out[con->num++] = *aud;
}

static void auditd_input(int fd)
{
  unsigned int scan = 0;
  struct auditd_msg aud;
  ssize_t len = read_all(fd, &aud.hdr, sizeof(aud.hdr), FALSE);

  if ((len == -1) && (errno == EAGAIN))
    return;
  if (len == -1)
    die("input read: %m");
  if (!len) /* FIXME: output stuff left ? */
    die("input read: EOF");
  
  if (aud.hdr.ver != AUDISP_PROTOCOL_VER)
    die("Wrong header version. got=%d expected=%d",
        (int)aud.hdr.ver, (int)AUDISP_PROTOCOL_VER);
  if (aud.hdr.hlen != sizeof(aud.hdr))
    die("Wrong header size. got=%zu expected=%zu",
        (size_t)aud.hdr.hlen, sizeof(aud.hdr));
  if (aud.hdr.size > MAX_AUDIT_MESSAGE_LENGTH)
    die("Bad header data size. got=%zu max=%zu",
        (size_t)aud.hdr.size, (size_t)MAX_AUDIT_MESSAGE_LENGTH);

  /* block waiting for input, it's too painful otherwise */
  len = read_all(fd, &aud.msg, aud.hdr.size, TRUE);
  if ((size_t)len != aud.hdr.size)
    die("didn't read correct data length. got=%zd, expected=%zu",
        len, (size_t)aud.hdr.size);

  for (; scan <= st_poll__max; ++scan)
  {
    if (!con_data[scan].active || 
        (con_data_used_num(con_data + scan) >= CONF_CON_OUT_SZ))
      continue;

    st_poll__fds[scan].events |= POLLOUT;
    con_data_add(con_data + scan, &aud);
  }

  auditd_input(fd);
}

static void con_add(int fd)
{
  io_poll_add(fd, 0);
  con_data[fd].used = con_data[fd].num = con_data[fd].off = 0;
  con_data[fd].active = TRUE;
}

static void con_accept(int listen_fd)
{
  int fd = -1;

  if ((fd = accept(listen_fd, NULL, 0)) == -1)
    return;

  if (fd <= CONF_CON_NUM_SZ)
    con_add(fd);
  else
  {
    syslog(LOG_WARNING, " Too many connections: max = %d", CONF_CON_NUM_SZ);
    close(fd);
  }
}

static void con_output(int fd)
{
  size_t len = 0;
  ssize_t ret = 0;
  struct con_data *con = con_data + fd;
  struct audit_dispatcher_header *hdr = &con->out[con->off].hdr;
  char *msg = con->out[con->off].msg;
  
  if (con->used >= hdr->hlen)
  {
    len = (hdr->size - (con->used - hdr->hlen));
    ret = write(fd, msg, len);
  }
  else
  {
    struct iovec vec[2];
    
    vec[0].iov_base = hdr;
    vec[0].iov_len  = hdr->hlen - con->used;
    vec[1].iov_base = msg;
    vec[1].iov_len  = hdr->size;

    len = vec[0].iov_len + vec[1].iov_len;
    ret = writev(fd, vec, 2);
  }

  if (ret == -1)
  {
    if (errno == EAGAIN)
      return;
    syslog(LOG_WARNING, " writev(%d): %m", fd);

    con->active = FALSE;
    io_poll_del(fd);
    close(fd);
    return;
  }
  
  if ((size_t)ret != len)
    con->used += ret;
  else
  {
    con->used = 0;
    
    if (++con->off == con->num)
    {
      st_poll__fds[fd].events &= ~POLLOUT;
      con->off = con->num = 0;
    }
  }
}

static int pipe_fd = -1; /* input from auditd */
static int locl_fd = -1; /* input from local socket */

static void io_poll_loop(void)
{
  unsigned int scan = 0;
  
  if ((locl_fd != -1) && (st_poll__fds[locl_fd].revents & POLLIN))
    con_accept(locl_fd);
  if ((pipe_fd != -1) && (st_poll__fds[pipe_fd].revents & POLLIN))
    auditd_input(pipe_fd);
  
  for (; scan <= st_poll__max; ++scan)
  {
    if (st_poll__fds[scan].revents & POLLOUT)
      con_output(scan);
  }
}

static void cmd_add(const char *path, const char *arg1, const char *arg2,
                    const char *arg3, const char *arg4, const char *arg5,
                    const char *arg6, const char *arg7, const char *arg8)
{ /* start a managed connection */
  int fds[2];
  pid_t pid = -1;
  
  if (pipe(fds) == -1)
    die("socketpair(): %m");
  
  switch ((pid = fork()))
  {
    case -1: die("fork(): %m");
      
    case 0: /* child */
      close(fds[1]);
      if (dup2(fds[0], STDIN_FILENO) == -1)
        die("dup2(STDIN)");
      if (dup2(fds[0], STDOUT_FILENO) == -1) /* note will fail */
        die("dup2(STDOUT)");
      close(fds[0]);
      execl(path, path, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
            (char *)NULL);
      die("execl(%s): %m", path);
      break;
      
    default:
      break;
  }

  con_add(fds[1]);

  syslog(LOG_NOTICE, "Started managed-connection: %s pid=%ld", path, (long)pid);
}

static void io_bind_local(void)
{
  const char *fname = CONF_AF_LOCAL_PATH;
  size_t len = strlen(fname) + 1;
  struct sockaddr_un tmp_sun;
  struct sockaddr_un *saddr = NULL;

  if ((locl_fd = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1)
    die("socket: %m");

  saddr = &tmp_sun; /* assume it's OK */
  saddr->sun_family = AF_LOCAL;
  memcpy(saddr->sun_path, fname, len);

  unlink(fname);
  if (bind(locl_fd, (struct sockaddr *)saddr, SUN_LEN(saddr)) == -1)
    die("bind(%s): %m", fname);
  if (chmod(fname, 0400) == -1)
    die("chmod(%s): %m", fname);
  if (listen(locl_fd, 16) == -1)
    die("listen(%s): %m", fname);

  io_poll_add(locl_fd, POLLIN);
}

static volatile int signaled = 0;
static void term_handler(int sig)
{
  (void)sig;
  signaled = 1;
}

int main(void)
{
  struct sigaction sa;

  openlog("audispd", LOG_PID, CONF_SYSLOG_PRIO);
  syslog(LOG_NOTICE, "listening on %s", CONF_AF_LOCAL_PATH);

#ifdef NDEBUG
  /* Make sure we are root */
  if (getuid() != 0)
    die("You must be root to run this program.");
#endif

  /* register sighandlers */
  sa.sa_flags   = 0;
  sa.sa_handler = term_handler;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGTERM, &sa, NULL ) == -1)
    die("sigaction(SIGTERM): %m");
  sa.sa_handler = term_handler;
  if (sigaction(SIGCHLD, &sa, NULL ) == -1)
    die("sigaction(SIGCHLD): %m");
  sa.sa_handler = SIG_IGN;
  if (sigaction(SIGHUP, &sa, NULL ) == -1)
    die("sigaction(SIGHUP): %m");

  if (chdir(CONF_CHDIR_PATH) == -1)
    die("chdir(%s): %m", CONF_CHDIR_PATH);
  
  /* change over to pipe_fd */
  if ((pipe_fd = dup(STDIN_FILENO)) == -1)
    die("dup(STDIN_FILENO): %m");

  /* close "std" fds, so nothing gets confused etc. */
  if (close(STDIN_FILENO) == -1)
    die("open(STDIN_FILENO): %m");
  if (open("/dev/null", O_RDONLY) == -1)
    die("open(%s): %m", "/dev/null");
  if (close(STDOUT_FILENO) == -1)
    die("open(STDOUT_FILENO): %m");
  if (open("/dev/null", O_WRONLY) == -1)
    die("open(%s): %m", "/dev/null");
  if (close(STDERR_FILENO) == -1)
    die("open(STDERR_FILENO): %m");
  if (open("/dev/null", O_WRONLY) == -1)
    die("open(%s): %m", "/dev/null");

  /* init data structures */
  io_poll_init();
  con_init();

  /* setup input */
  io_poll_add(pipe_fd, POLLIN);

  /* setup connections */
  io_bind_local();

#ifdef TST /* FIXME: needs config. */
  cmd_add("/usr/sbin/audispd-plugin", "--daemon", "/tmp/audispd-plugin-output",
          NULL, NULL, NULL, NULL, NULL, NULL);
#endif
  
  while (!signaled)
  {
    io_poll_block();
    io_poll_loop(); 
  }
  
  {
    pid_t cpid = -1;
    
    if ((cpid = waitpid(-1, NULL, WNOHANG)) != -1)
      syslog(LOG_NOTICE, "Child %ld died", (long)cpid);
  }
  
  unlink(CONF_AF_LOCAL_PATH);
  
  syslog(LOG_NOTICE, "exiting");
  
  exit (EXIT_SUCCESS);
}
