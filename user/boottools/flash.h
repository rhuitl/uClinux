#ifndef __FLASH_H__
#define __FLASH_H__

/* Command codes for the flash_command routine */
#define FLASH_SELECT    0       /* no command; just perform the mapping */
#define FLASH_RESET     1       /* reset to read mode */
#define FLASH_READ      1       /* reset to read mode, by any other name */
#define FLASH_AUTOSEL   2       /* autoselect (fake Vid on pin 9) */
#define FLASH_PROG      3       /* program a word */
#define FLASH_CERASE    4       /* chip erase */
#define FLASH_SERASE    5       /* sector erase */
#define FLASH_ESUSPEND  6       /* suspend sector erase */
#define FLASH_ERESUME   7       /* resume sector erase */
#define FLASH_UB        8       /* go into unlock bypass mode */
#define FLASH_UBPROG    9       /* program a word using unlock bypass */
#define FLASH_UBRESET   10      /* reset to read mode from unlock bypass mode */
#define FLASH_LASTCMD   10      /* used for parameter checking */

/* Return codes from flash_status */
#define STATUS_READY    0       /* ready for action */
#define STATUS_BUSY     1       /* operation in progress */
#define STATUS_ERSUSP   2       /* erase suspended */
#define STATUS_TIMEOUT  3       /* operation timed out */
#define STATUS_ERROR    4       /* unclassified but unhappy status */

/* manufacturer ID */
#define AMDPART   	0x01
#define TOSPART		0x98
#define SSTPART		0xbf
#define ATPART		0x1f

/* A list of 4 AMD device ID's - add others as needed */
#define ID_AM29DL800T   0x224A
#define ID_AM29DL800B   0x22CB
#define ID_AM29LV800T   0x22DA
#define ID_AM29LV800B   0x225B
#define ID_AM29LV160B   0x2249
#define ID_AM29LV160T   0x22C4
#define ID_TC58FVT160	0x00C2
#define ID_TC58FVB160	0x0043
#define ID_TC58FVB160X2	0x00430043
#define ID_AM29LV400B   0x22BA
#define ID_AT49BV1614   0x00C0
#define ID_SST39VF160   0x2782
/* definition for arm7tdni */
#define ID_AT27LV1024	0x0000
#define ID_AT29LV1024	0x0001

#define SECTOR_DIRTY   0x01
#define SECTOR_ERASED  0x02
#define SECTOR_PROTECT 0x04

#define PGM_ERASE_FIRST 0x0001
#define PGM_RESET_AFTER 0x0002
#define PGM_EXEC_AFTER  0x0004
#define PGM_HALT_AFTER  0x0008
#define PGM_DEBUG       0x0010

#endif /* __FLASH_H__ */


