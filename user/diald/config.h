/*
 * config.h - Configuration options for diald.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 *
 * These are the compile time defaults for various system files.
 * You may want to edit these to match your system before you compile diald.
 * However, if you didn't, don't panic. Almost all of these locations can be
 * configured at run time if necessary. The only thing you can't configure
 * at run time is the location of the main diald configuration files.
 *
 */

/*
 * Diald needs to be able to find its default configuration files.
 * These paths should match the installation path in the Makefile!
 * THIS MUST BE CONFIGURED AT COMPILE TIME IF YOU WANT TO CHANGE IT!
 */
#define DIALD_CONFIG_FILE "/etc/config/diald.conf"
#define DIALD_DEFS_FILE "/etc/diald.defs"


/*****************************************************************************
 * EVERYTHING BELOW HERE IS RUN TIME CONFIGURABLE
 * You can change these things if you want to save yourself some
 * entries in your configuration files.
 ****************************************************************************/

/* You're lock files are probably somewhere else unless you
 * happen to be running a newer distribution that is compiliant
 * the the Linux File System Standard. On older distributions
 * you will usually find them in /var/spool/uucp or /usr/spool/uucp.
 */
#define LOCK_PREFIX	"/var/lock/LCK.."

/*
 * If you're lock files should contain binary PID's then
 * set the following to 0. I think most linux
 * distributions want ASCII PID's in the lock files.
 */
#define PIDSTRING 1

/* Define where to put the diald.pid file. Under the FSSTD this 
 * should be in /var/run, but you're system might have them
 * elsewhere. Check and be sure.
 */
#define RUN_PREFIX	"/var/run"

/*
 * Diald needs to use the route and ifconfig binaries to set up
 * routing tables and to bring up the proxy device. Check where
 * these executables are on your system and set these paths to match.
 */
#if CONFIG_USER_NET_TOOLS_IFCONFIG 
#define PATH_IFCONFIG	"/sbin/ifconfig"
#else
#define PATH_IFCONFIG	"/bin/ifconfig"
#endif

#if CONFIG_USER_NET_TOOLS_ROUTE
#define PATH_ROUTE	"/sbin/route"
#else
#define PATH_ROUTE	"/bin/route"
#endif

#define SL_DOWN " sl%d down"
#define SL_UP " sl%d up"

/*
 * We need some defaults for metrics that are compatible
 * with our firewall rules,  but can also be overriden
 */

#define	DEFAULT_INTERFACE_METRIC	0
#define	DEFAULT_DEFAULT_ROUTE_METRIC	0

/*
 * Diald needs to know where to find the bootpc binary in order to
 * use the bootp protocol for dynamic slip address determination.
 */

#define PATH_BOOTPC	"/bin/bootpc"

/*
 * I you're never going to use pppd don't worry if this is wrong.
 * Otherwise, find your pppd executable and set this path to match its
 * location.
 */
#define PATH_PPPD	"/bin/pppd"
