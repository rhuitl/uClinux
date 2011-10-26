/*
 * Copyright (C) 2006 Free Software Initiative of Japan
 *
 * Author: NIIBE Yutaka  <gniibe at fsij.org>
 * Modified by: Kenneth Wilson <ken_wilson at securecomputing.com>
 *
 * This file can be distributed under the terms and conditions of the
 * GNU General Public License version 2 (or later).
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>

#define USBDEVFS_IOCTL             _IOWR('U', 18, struct usbdevfs_ioctl)
#define USBDEVFS_HUB_PORTCTRL      _IOW('U', 24, struct usbdevfs_hub_portctrl)

struct usbdevfs_ioctl {
  int ifno;
  int ioctl_code;
  void *data;
};

struct usbdevfs_hub_portctrl {
  char port;
  char value;
};

static void
usage (const char *progname)
{
  fprintf (stderr, "Usage: %s PATH PORT on|off\n", progname);
}

/*
 * HUB-CTRL  -  program to control port power of USB hub
 *
 *   $ hub-ctrl /dev/bus/usb/001/002 1 off           # Power off at port 1
 *   $ hub-ctrl /dev/bus/usb/001/002 1 on          # Power on at port 1
 *
 * Requirements: Hub that supports this function.
 *
 */
int
main (int argc, const char *argv[])
{
  int fd;
  struct usbdevfs_ioctl ioctl_data;
  struct usbdevfs_hub_portctrl portctrl_data;
  const char *path;
  int port = 1;
  int value = 0;

  if (argc < 4)
    {
      usage (argv[0]);
      exit (1);
    }

  path = argv[1];
  port = atoi(argv[2]);
  if (strcmp(argv[3], "on") == 0) 
    value = 1;

  if ((fd = open (path, O_RDWR)) < 0)
    {
      perror ("open");
      exit (1);
    }

  ioctl_data.ifno = 0;
  ioctl_data.ioctl_code = USBDEVFS_HUB_PORTCTRL;
  ioctl_data.data = &portctrl_data;

  portctrl_data.port = port;
  portctrl_data.value = value;

  if (ioctl (fd, USBDEVFS_IOCTL, &ioctl_data) < 0)
    {
      perror ("ioctl");
      close (fd);
      exit (1);
    }

  close (fd);
  exit (0);
}
