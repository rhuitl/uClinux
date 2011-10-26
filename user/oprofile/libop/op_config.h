/**
 * @file op_config.h
 *
 * Parameters a user may want to change. See
 * also op_config_24.h
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author Philippe Elie
 */

#ifndef OP_CONFIG_H
#define OP_CONFIG_H

/* various paths, duplicated in opcontrol */
#define OP_BASE_DIR "/var/lib/oprofile/"
#define OP_SAMPLES_DIR OP_BASE_DIR "samples/"
#define OP_SAMPLES_CURRENT_DIR OP_SAMPLES_DIR "current/"
#define OP_LOCK_FILE OP_BASE_DIR "lock"
#define OP_LOG_FILE OP_BASE_DIR "oprofiled.log"
#define OP_DUMP_STATUS OP_BASE_DIR "complete_dump"

/* Global directory that stores debug files */
#ifndef DEBUGDIR
#define DEBUGDIR "/usr/lib/debug"
#endif

#define OPD_MAGIC "DAE\n"
#define OPD_VERSION 0x10

#define OP_MIN_CPU_BUF_SIZE 2048
#define OP_MAX_CPU_BUF_SIZE 131072

#endif /* OP_CONFIG_H */
