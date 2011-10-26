/* $Id: frob-led.c,v 1.4 2004-08-18 06:01:20 philipc Exp $ */

/*
 * Trivial utility to allow frobbing of NETtel LEDs from scripts.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/ledman.h>

#include "keywords.h"

static void usage (const char *jane)
{
  const table_t *t;
  fprintf(stderr, "usage: %s <cmd> <led>\n", jane);
  fprintf(stderr, "\n\t<cmd>:\n");
  for (t = cmds; t->name; t++)
    fprintf(stderr, "\t\t%s\n", t->name);
  fprintf(stderr, "\n\t<led>:\n");
  for (t = leds; t->name; t++)
    fprintf(stderr, "\t\t%s\n", t->name);
  exit(1);
}

static const table_t *find(const table_t *t, const char *name)
{
  while (t->name && strcasecmp(name, t->name))
    t++;
  return (t->name ? t : 0);
}

int main (int argc, char *argv[])
{
  const table_t *cmd, *led;
  int alt = 0;
  const char* myname = argv[0];

  if (argc>=2 && strcmp(argv[1], "-a")==0) {
    argv++;
    argc--;
    alt = LEDMAN_CMD_ALTBIT;
  }
  if (argc != 3 ||
      !(cmd = find(cmds, argv[1])))
    usage(myname);
  if (cmd->value == LEDMAN_CMD_MODE) {
    ledman_cmd(cmd->value, argv[2]);
  }
  else {
    if (!(led = find(leds, argv[2])))
      usage(myname);
    ledman_cmd(cmd->value|alt, led->value);
  }
  return 0;
}
