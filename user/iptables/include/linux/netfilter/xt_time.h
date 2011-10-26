#ifndef _XT_TIME_H
#define _XT_TIME_H 1

struct xt_time_info {
	u_int32_t date_start;
	u_int32_t date_stop;
	u_int32_t daytime_start;
	u_int32_t daytime_stop;
	u_int32_t monthdays_match;
	u_int8_t weekdays_match;
	u_int8_t flags;
};

struct xt_time_priv;

struct xt_time_info1 {
	u_int32_t date_start;
	u_int32_t date_stop;
	u_int32_t daytime_start;
	u_int32_t daytime_stop;
	u_int32_t monthdays_match;
	u_int8_t weekdays_match;
	u_int8_t flags;
	struct {
		char name[7];
		u_int8_t type;    /* XT_TIME_TZ_TYPE_* */
		u_int8_t month;   /* 1-12 */
		u_int8_t week;    /* 1-5 */
		u_int16_t day;    /* 0-6 or 0-365 or 1-365 */
		u_int32_t secs;
		int32_t offset;
	} tz[2];
	struct xt_time_priv *master;
};

enum {
	/* Match against local time (instead of UTC) */
	XT_TIME_LOCAL_TZ = 1 << 0,
	/* Match against given timezone (instead of UTC) */
	XT_TIME_TZ       = 1 << 1,

	XT_TIME_TZ_TYPE_J0 = 0, /* Zero-based Julian day, 0-365 */
	XT_TIME_TZ_TYPE_J1 = 1, /* Julian day, 1-365, no leap day */
	XT_TIME_TZ_TYPE_M  = 2, /* Month, week and day */

	/* Shortcuts */
	XT_TIME_ALL_MONTHDAYS = 0xFFFFFFFE,
	XT_TIME_ALL_WEEKDAYS  = 0xFE,
	XT_TIME_MIN_DAYTIME   = 0,
	XT_TIME_MAX_DAYTIME   = 24 * 60 * 60 - 1,
};

#endif /* _XT_TIME_H */
