#ifndef WPA_SUPPLICANT_H
#define WPA_SUPPLICANT_H

/* Driver wrappers are not supposed to directly touch the internal data
 * structure used in wpa_supplicant, so that definition is not provided here.
 */
struct wpa_supplicant;

typedef enum {
	EVENT_ASSOC, EVENT_DISASSOC, EVENT_MICHAEL_MIC_FAILURE,
	EVENT_SCAN_RESULTS, EVENT_ASSOCINFO, EVENT_INTERFACE_STATUS,
} wpa_event_type;

union wpa_event_data {
	struct {
		/* Optional request information data: IEs included in AssocReq
		 * and AssocResp. If these are not returned by the driver,
		 * WPA Supplicant will generate the WPA IE. */
		u8 *req_ies, *resp_ies;
		size_t req_ies_len, resp_ies_len;
	} assoc_info;
	struct {
		int unicast;
	} michael_mic_failure;
	struct {
		char ifname[20];
		enum {
			EVENT_INTERFACE_ADDED, EVENT_INTERFACE_REMOVED
		} ievent;
	} interface_status;
};

/**
 * wpa_supplicant_event - report a driver event for wpa_supplicant
 * @wpa_s: pointer to wpa_supplicant data; this is the @ctx variable registered
 *	with wpa_driver_events_init()
 * @event: event type (defined above)
 * @data: possible extra data for the event
 *
 * Driver wrapper code should call this function whenever an event is received
 * from the driver.
 */
void wpa_supplicant_event(struct wpa_supplicant *wpa_s, wpa_event_type event,
			  union wpa_event_data *data);


/* Debugging function - conditional printf and hex dump. Driver wrappers can
 *  use these for debugging purposes. */

enum { MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR };

/**
 * wpa_printf - conditional printf
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration.
 *
 * Note: New line '\n' is added to the end of the text when printing to stdout.
 */
void wpa_printf(int level, char *fmt, ...)
__attribute__ ((format (printf, 2, 3)));

/**
 * wpa_msg - conditional printf for default target and ctrl_iface monitors
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. This function is like wpa_printf(), but it also sends the
 * same message to all attached ctrl_iface monitors.
 *
 * Note: New line '\n' is added to the end of the text when printing to stdout.
 */
void wpa_msg(struct wpa_supplicant *wpa_s, int level, char *fmt, ...)
__attribute__ ((format (printf, 3, 4)));

/**
 * wpa_hexdump - conditional hex dump
 * @level: priority level (MSG_*) of the message
 * @title: title of for the message
 * @buf: data buffer to be dumped
 * @len: length of the @buf
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. The contents of @buf is printed out has hex dump.
 */
void wpa_hexdump(int level, const char *title, const u8 *buf, size_t len);

/**
 * wpa_hexdump_ascii - conditional hex dump
 * @level: priority level (MSG_*) of the message
 * @title: title of for the message
 * @buf: data buffer to be dumped
 * @len: length of the @buf
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. The contents of @buf is printed out has hex dump with both
 * the hex numbers and ASCII characters (for printable range) are shown. 16
 * bytes per line will be shown.
 */
void wpa_hexdump_ascii(int level, const char *title, const u8 *buf,
		       size_t len);

const char * wpa_ssid_txt(u8 *ssid, size_t ssid_len);

#endif /* WPA_SUPPLICANT_H */
