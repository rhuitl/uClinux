/*
 * voice_paths.h
 *
 * This file contains the position of the configuration file and of
 * the logfiles. Change this for your installation.
 *
 * $Id: paths.h,v 1.4 1998/09/09 21:06:36 gert Exp $
 *
 */

/*
 * Filename of the voice configuration file.
 */

#define VOICE_CONFIG_FILE "voice.conf"

/*
 * Filename of the logfile for vgetty. The "%s" will be replaced by
 * the device name.
 */

#define VGETTY_LOG_PATH "/var/log/vgetty.%s"

/*
 * Filename of the logfile for vm.
 */

#define VM_LOG_PATH "/var/log/vm.log"
