/*
 * WPA Supplicant / Configuration file parser
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <grp.h>

#include "common.h"
#include "wpa.h"
#include "config.h"
#include "sha1.h"
#include "wpa_supplicant.h"
#include "eapol_sm.h"
#include "eap.h"


static char * wpa_config_get_line(char *s, int size, FILE *stream, int *line)
{
	char *pos, *end, *sstart;

	while (fgets(s, size, stream)) {
		(*line)++;
		s[size - 1] = '\0';
		pos = s;

		while (*pos == ' ' || *pos == '\t')
			pos++;
		if (*pos == '#' || *pos == '\n' || *pos == '\0')
			continue;

		/* Remove # comments unless they are within a double quoted
		 * string. Remove trailing white space. */
		sstart = strchr(pos, '"');
		if (sstart)
			sstart = strchr(sstart + 1, '"');
		if (!sstart)
			sstart = pos;
		end = strchr(sstart, '#');
		if (end)
			*end-- = '\0';
		else
			end = pos + strlen(pos) - 1;
		while (end > pos &&
		       (*end == '\n' || *end == ' ' || *end == '\t')) {
			*end-- = '\0';
		}
		if (*pos == '\0')
			continue;

		return pos;
	}

	return NULL;
}


static char * wpa_config_parse_string(const char *value, size_t *len)
{

	if (*value == '"') {
		char *pos;
		value++;
		pos = strchr(value, '"');
		if (pos == NULL || pos[1] != '\0') {
			value--;
			return NULL;
		}
		*pos = '\0';
		*len = strlen(value);
		return strdup(value);
	} else {
		char *str;
		int hlen = strlen(value);
		if (hlen % 1)
			return NULL;
		*len = hlen / 2;
		str = malloc(*len);
		if (str == NULL)
			return NULL;
		if (hexstr2bin(value, str, *len)) {
			free(str);
			return NULL;
		}
		return str;
	}
}


static int wpa_config_parse_ssid(struct wpa_ssid *ssid, int line,
				 const char *value)
{
	free(ssid->ssid);
	ssid->ssid = wpa_config_parse_string(value, &ssid->ssid_len);
	if (ssid->ssid == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: Invalid SSID '%s'.",
			   line, value);
		return -1;
	}
	if (ssid->ssid_len > MAX_SSID_LEN) {
		free(ssid->ssid);
		wpa_printf(MSG_ERROR, "Line %d: Too long SSID '%s'.",
			   line, value);
		return -1;
	}
	wpa_hexdump_ascii(MSG_MSGDUMP, "SSID", ssid->ssid, ssid->ssid_len);
	return 0;
}


static int wpa_config_parse_scan_ssid(struct wpa_ssid *ssid, int line,
				      const char *value)
{
	if (value[0] == '1')
		ssid->scan_ssid = 1;
	else if (value[0] == '0')
		ssid->scan_ssid = 0;
	else {
		wpa_printf(MSG_ERROR, "Line %d: invalid scan_ssid setting '%s'"
			   " (expected 0 or 1)", line, value);
		return -1;
	}
	return 0;
}


static int wpa_config_parse_bssid(struct wpa_ssid *ssid, int line,
				  const char *value)
{
	if (hwaddr_aton(value, ssid->bssid)) {
		wpa_printf(MSG_ERROR, "Line %d: Invalid BSSID '%s'.",
			   line, value);
		return -1;
	}
	ssid->bssid_set = 1;
	wpa_hexdump(MSG_MSGDUMP, "BSSID", ssid->bssid, ETH_ALEN);
	return 0;
}


static int wpa_config_parse_psk(struct wpa_ssid *ssid, int line,
				const char *value)
{
	if (*value == '"') {
		char *pos;
		int len;

		value++;
		pos = strrchr(value, '"');
		if (pos)
			*pos = '\0';
		len = strlen(value);
		if (len < 8 || len > 63) {
			wpa_printf(MSG_ERROR, "Line %d: Invalid passphrase "
				   "length %d (expected: 8..63) '%s'.",
				   line, len, value);
			return -1;
		}
		wpa_hexdump_ascii(MSG_MSGDUMP, "PSK (ASCII passphrase)",
				  value, len);
		ssid->passphrase = strdup(value);
		return ssid->passphrase == NULL ? -1 : 0;
	}

	if (hexstr2bin(value, ssid->psk, PMK_LEN) ||
	    value[PMK_LEN * 2] != '\0') {
		wpa_printf(MSG_ERROR, "Line %d: Invalid PSK '%s'.",
			   line, value);
		return -1;
	}
	ssid->psk_set = 1;
	wpa_hexdump(MSG_MSGDUMP, "PSK", ssid->psk, PMK_LEN);
	return 0;
}


static int wpa_config_parse_proto(struct wpa_ssid *ssid, int line,
				  const char *value)
{
	int val = 0, last, errors = 0;
	char *start, *end, *buf;

	buf = strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (start != '\0') {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		if (strcmp(start, "WPA") == 0)
			val |= WPA_PROTO_WPA;
		else if (strcmp(start, "RSN") == 0 ||
			 strcmp(start, "WPA2") == 0)
			val |= WPA_PROTO_RSN;
		else {
			wpa_printf(MSG_ERROR, "Line %d: invalid proto '%s'",
				   line, start);
			errors++;
		}

		if (last)
			break;
		start = end + 1;
	}
	free(buf);

	if (val == 0) {
		wpa_printf(MSG_ERROR,
			   "Line %d: no proto values configured.", line);
		errors++;
	}

	wpa_printf(MSG_MSGDUMP, "proto: 0x%x", val);
	ssid->proto = val;
	return errors ? -1 : 0;
}


static int wpa_config_parse_key_mgmt(struct wpa_ssid *ssid, int line,
				     const char *value)
{
	int val = 0, last, errors = 0;
	char *start, *end, *buf;

	buf = strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (start != '\0') {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		if (strcmp(start, "WPA-PSK") == 0)
			val |= WPA_KEY_MGMT_PSK;
		else if (strcmp(start, "WPA-EAP") == 0)
			val |= WPA_KEY_MGMT_IEEE8021X;
		else if (strcmp(start, "IEEE8021X") == 0)
			val |= WPA_KEY_MGMT_IEEE8021X_NO_WPA;
		else if (strcmp(start, "NONE") == 0)
			val |= WPA_KEY_MGMT_NONE;
		else {
			wpa_printf(MSG_ERROR, "Line %d: invalid key_mgmt '%s'",
				   line, start);
			errors++;
		}

		if (last)
			break;
		start = end + 1;
	}
	free(buf);

	if (val == 0) {
		wpa_printf(MSG_ERROR,
			   "Line %d: no key_mgmt values configured.", line);
		errors++;
	}

	wpa_printf(MSG_MSGDUMP, "key_mgmt: 0x%x", val);
	ssid->key_mgmt = val;
	return errors ? -1 : 0;
}


static int wpa_config_parse_cipher(struct wpa_ssid *ssid, int line,
				   const char *value)
{
	int val = 0, last;
	char *start, *end, *buf;

	buf = strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (start != '\0') {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		if (strcmp(start, "CCMP") == 0)
			val |= WPA_CIPHER_CCMP;
		else if (strcmp(start, "TKIP") == 0)
			val |= WPA_CIPHER_TKIP;
		else if (strcmp(start, "WEP104") == 0)
			val |= WPA_CIPHER_WEP104;
		else if (strcmp(start, "WEP40") == 0)
			val |= WPA_CIPHER_WEP40;
		else if (strcmp(start, "NONE") == 0)
			val |= WPA_CIPHER_NONE;
		else {
			wpa_printf(MSG_ERROR, "Line %d: invalid cipher '%s'.",
				   line, start);
			return -1;
		}

		if (last)
			break;
		start = end + 1;
	}

	if (val == 0) {
		wpa_printf(MSG_ERROR, "Line %d: no cipher values configured.",
			   line);
		return -1;
	}
	return val;
}


static int wpa_config_parse_pairwise(struct wpa_ssid *ssid, int line,
				     const char *value)
{
	int val;
	val = wpa_config_parse_cipher(ssid, line, value);
	if (val == -1)
		return -1;
	if (val & ~(WPA_CIPHER_CCMP | WPA_CIPHER_TKIP | WPA_CIPHER_NONE)) {
		wpa_printf(MSG_ERROR, "Line %d: not allowed pairwise cipher "
			   "(0x%x).", line, val);
		return -1;
	}

	wpa_printf(MSG_MSGDUMP, "pairwise: 0x%x", val);
	ssid->pairwise_cipher = val;
	return 0;
}


static int wpa_config_parse_group(struct wpa_ssid *ssid, int line,
				  const char *value)
{
	int val;
	val = wpa_config_parse_cipher(ssid, line, value);
	if (val == -1)
		return -1;
	if (val & ~(WPA_CIPHER_CCMP | WPA_CIPHER_TKIP | WPA_CIPHER_WEP104 |
		    WPA_CIPHER_WEP40)) {
		wpa_printf(MSG_ERROR, "Line %d: not allowed group cipher "
			   "(0x%x).", line, val);
		return -1;
	}

	wpa_printf(MSG_MSGDUMP, "group: 0x%x", val);
	ssid->group_cipher = val;
	return 0;
}


static u8 wpa_config_eap_txt_to_type(const char *value)
{
#ifdef EAP_MD5
	if (strcmp(value, "MD5") == 0)
		return EAP_TYPE_MD5;
#endif /* EAP_MD5 */
#ifdef EAP_TLS
	if (strcmp(value, "TLS") == 0)
		return EAP_TYPE_TLS;
#endif /* EAP_TLS */
#ifdef EAP_PEAP
	if (strcmp(value, "PEAP") == 0)
		return EAP_TYPE_PEAP;
#endif /* EAP_PEAP */
#ifdef EAP_TTLS
	if (strcmp(value, "TTLS") == 0)
		return EAP_TYPE_TTLS;
#endif /* EAP_TTLS */
#ifdef EAP_MSCHAPv2
	if (strcmp(value, "MSCHAPV2") == 0)
		return EAP_TYPE_MSCHAPV2;
#endif /* EAP_MSCHAPv2 */
#ifdef EAP_GTC
	if (strcmp(value, "GTC") == 0)
		return EAP_TYPE_GTC;
#endif /* EAP_GTC */
#ifdef EAP_OTP
	if (strcmp(value, "OTP") == 0)
		return EAP_TYPE_OTP;
#endif /* EAP_OTP */
#ifdef EAP_SIM
	if (strcmp(value, "SIM") == 0)
		return EAP_TYPE_SIM;
#endif /* EAP_SIM */
#ifdef EAP_LEAP
	if (strcmp(value, "LEAP") == 0)
		return EAP_TYPE_LEAP;
#endif /* EAP_LEAP */
	return EAP_TYPE_NONE;
}


static int wpa_config_parse_eap(struct wpa_ssid *ssid, int line,
				const char *value)
{
	int last, errors = 0;
	char *start, *end, *buf, *methods = NULL, *tmp;
	size_t num_methods = 0;

	buf = strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (start != '\0') {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		tmp = methods;
		methods = realloc(methods, num_methods + 1);
		if (methods == NULL) {
			free(tmp);
			return -1;
		}
		methods[num_methods] = wpa_config_eap_txt_to_type(start);
		if (methods[num_methods] == EAP_TYPE_NONE) {
			wpa_printf(MSG_ERROR, "Line %d: unknown EAP method "
				   "'%s'", line, start);
			wpa_printf(MSG_ERROR, "You may need to add support for"
				   " this EAP method during wpa_supplicant\n"
				   "build time configuration.\n"
				   "See README for more information.");
			errors++;
		} else if (methods[num_methods] == EAP_TYPE_LEAP)
			ssid->leap++;
		else
			ssid->non_leap++;
		num_methods++;
		if (last)
			break;
		start = end + 1;
	}
	free(buf);

	tmp = methods;
	methods = realloc(methods, num_methods + 1);
	if (methods == NULL) {
		free(tmp);
		return -1;
	}
	methods[num_methods] = EAP_TYPE_NONE;
	num_methods++;

	wpa_hexdump(MSG_MSGDUMP, "eap methods", methods, num_methods);
	ssid->eap_methods = methods;
	return errors ? -1 : 0;
}


static int wpa_config_parse_identity(struct wpa_ssid *ssid, int line,
				     const char *value)
{
	free(ssid->identity);
	ssid->identity = wpa_config_parse_string(value, &ssid->identity_len);
	if (ssid->identity == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse identity "
			   "string '%s'", line, value);
		return -1;
	}
	wpa_hexdump_ascii(MSG_MSGDUMP, "identity", ssid->identity,
			  ssid->identity_len);
	return 0;
}


static int wpa_config_parse_anonymous_identity(struct wpa_ssid *ssid, int line,
					       const char *value)
{
	free(ssid->anonymous_identity);
	ssid->anonymous_identity =
		wpa_config_parse_string(value, &ssid->anonymous_identity_len);
	if (ssid->anonymous_identity == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse anonymous "
			   "identity string '%s'", line, value);
		return -1;
	}
	wpa_hexdump_ascii(MSG_MSGDUMP, "anonymous_identity",
			  ssid->anonymous_identity, ssid->identity_len);
	return 0;
}


static int wpa_config_parse_password(struct wpa_ssid *ssid, int line,
				     const char *value)
{
	free(ssid->password);
	ssid->password = wpa_config_parse_string(value, &ssid->password_len);
	if (ssid->password == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse password "
			   "string '%s'", line, value);
		return -1;
	}
	wpa_hexdump_ascii(MSG_MSGDUMP, "password", ssid->password,
			  ssid->password_len);
	return 0;
}


static int wpa_config_parse_ca_cert(struct wpa_ssid *ssid, int line,
				    const char *value)
{
	size_t len;
	free(ssid->ca_cert);
	ssid->ca_cert = wpa_config_parse_string(value, &len);
	if (ssid->ca_cert == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse CA "
			   "certificate string '%s'", line, value);
		return -1;
	}
	wpa_printf(MSG_MSGDUMP, "ca_cert=%s", ssid->ca_cert);
	return 0;
}


static int wpa_config_parse_client_cert(struct wpa_ssid *ssid, int line,
					const char *value)
{
	size_t len;
	free(ssid->client_cert);
	ssid->client_cert = wpa_config_parse_string(value, &len);
	if (ssid->client_cert == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse client "
			   "certificate string '%s'", line, value);
		return -1;
	}
	wpa_printf(MSG_MSGDUMP, "client_cert=%s", ssid->client_cert);
	return 0;
}


static int wpa_config_parse_private_key(struct wpa_ssid *ssid, int line,
					const char *value)
{
	size_t len;
	free(ssid->private_key);
	ssid->private_key = wpa_config_parse_string(value, &len);
	if (ssid->private_key == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse private "
			   "key string '%s'", line, value);
		return -1;
	}
	wpa_printf(MSG_MSGDUMP, "private_key=%s", ssid->private_key);
	return 0;
}


static int wpa_config_parse_private_key_passwd(struct wpa_ssid *ssid, int line,
					       const char *value)
{
	size_t len;
	free(ssid->private_key_passwd);
	ssid->private_key_passwd = wpa_config_parse_string(value, &len);
	if (ssid->private_key_passwd == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse private "
			   "key string '%s'", line, value);
		return -1;
	}
	wpa_printf(MSG_MSGDUMP, "private_key_passwd=%s",
		   ssid->private_key_passwd);
	return 0;
}


static int wpa_config_parse_ca_cert2(struct wpa_ssid *ssid, int line,
				     const char *value)
{
	size_t len;
	free(ssid->ca_cert2);
	ssid->ca_cert2 = wpa_config_parse_string(value, &len);
	if (ssid->ca_cert2 == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse CA "
			   "certificate string '%s'", line, value);
		return -1;
	}
	wpa_printf(MSG_MSGDUMP, "ca_cert2=%s", ssid->ca_cert2);
	return 0;
}


static int wpa_config_parse_client_cert2(struct wpa_ssid *ssid, int line,
					 const char *value)
{
	size_t len;
	free(ssid->client_cert2);
	ssid->client_cert2 = wpa_config_parse_string(value, &len);
	if (ssid->client_cert2 == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse client "
			   "certificate string '%s'", line, value);
		return -1;
	}
	wpa_printf(MSG_MSGDUMP, "client_cert2=%s", ssid->client_cert2);
	return 0;
}


static int wpa_config_parse_private_key2(struct wpa_ssid *ssid, int line,
					 const char *value)
{
	size_t len;
	free(ssid->private_key2);
	ssid->private_key2 = wpa_config_parse_string(value, &len);
	if (ssid->private_key2 == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse private "
			   "key string '%s'", line, value);
		return -1;
	}
	wpa_printf(MSG_MSGDUMP, "private_key2=%s", ssid->private_key2);
	return 0;
}


static int wpa_config_parse_private_key2_passwd(struct wpa_ssid *ssid,
						int line, const char *value)
{
	size_t len;
	free(ssid->private_key2_passwd);
	ssid->private_key2_passwd = wpa_config_parse_string(value, &len);
	if (ssid->private_key2_passwd == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse private "
			   "key string '%s'", line, value);
		return -1;
	}
	wpa_printf(MSG_MSGDUMP, "private_key2_passwd=%s",
		   ssid->private_key2_passwd);
	return 0;
}


static int wpa_config_parse_phase1(struct wpa_ssid *ssid, int line,
				   const char *value)
{
	size_t len;
	free(ssid->phase1);
	ssid->phase1 = wpa_config_parse_string(value, &len);
	if (ssid->phase1 == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse Phase1 "
			   "parameters '%s'", line, value);
		return -1;
	}
	wpa_printf(MSG_MSGDUMP, "phase1=%s", ssid->phase1);
	return 0;
}


static int wpa_config_parse_phase2(struct wpa_ssid *ssid, int line,
				   const char *value)
{
	size_t len;
	free(ssid->phase2);
	ssid->phase2 = wpa_config_parse_string(value, &len);
	if (ssid->phase2 == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse Phase2 "
			   "parameters '%s'", line, value);
		return -1;
	}
	wpa_printf(MSG_MSGDUMP, "phase2=%s", ssid->phase2);
	return 0;
}


static int wpa_config_parse_pcsc(struct wpa_ssid *ssid, int line,
				 const char *value)
{
	size_t len;
	free(ssid->pcsc);
	ssid->pcsc = wpa_config_parse_string(value, &len);
	if (ssid->pcsc == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse pcsc "
			   "parameters '%s'", line, value);
		return -1;
	}
	wpa_printf(MSG_MSGDUMP, "pcsc=%s", ssid->pcsc);
	return 0;
}


static int wpa_config_parse_pin(struct wpa_ssid *ssid, int line,
				const char *value)
{
	size_t len;
	free(ssid->pin);
	ssid->pin = wpa_config_parse_string(value, &len);
	if (ssid->pin == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse pin "
			   "parameters '%s'", line, value);
		return -1;
	}
	wpa_printf(MSG_MSGDUMP, "pin=%s", ssid->pin);
	return 0;
}


static int wpa_config_parse_eapol_flags(struct wpa_ssid *ssid, int line,
					const char *value)
{
	ssid->eapol_flags = atoi(value);
	wpa_printf(MSG_MSGDUMP, "eapol_flags=0x%x", ssid->eapol_flags);
	return 0;
}


static int wpa_config_parse_wep_key(u8 *key, size_t *len, int line,
				    const char *value, int idx)
{
	char *buf, title[20];

	buf = wpa_config_parse_string(value, len);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: Invalid WEP key %d '%s'.",
			   line, idx, value);
		return -1;
	}
	if (*len > MAX_WEP_KEY_LEN) {
		wpa_printf(MSG_ERROR, "Line %d: Too long WEP key %d '%s'.",
			   line, idx, value);
		free(buf);
		return -1;
	}
	memcpy(key, buf, *len);
	free(buf);
	snprintf(title, sizeof(title), "wep_key%d", idx);
	wpa_hexdump(MSG_MSGDUMP, title, key, *len);
	return 0;
}


static int wpa_config_parse_wep_key0(struct wpa_ssid *ssid, int line,
				     const char *value)
{
	return wpa_config_parse_wep_key(ssid->wep_key[0],
					&ssid->wep_key_len[0], line, value, 0);
}


static int wpa_config_parse_wep_key1(struct wpa_ssid *ssid, int line,
				     const char *value)
{
	return wpa_config_parse_wep_key(ssid->wep_key[1],
					&ssid->wep_key_len[1], line, value, 1);
}


static int wpa_config_parse_wep_key2(struct wpa_ssid *ssid, int line,
				     const char *value)
{
	return wpa_config_parse_wep_key(ssid->wep_key[2],
					&ssid->wep_key_len[2], line, value, 2);
}


static int wpa_config_parse_wep_key3(struct wpa_ssid *ssid, int line,
				     const char *value)
{
	return wpa_config_parse_wep_key(ssid->wep_key[3],
					&ssid->wep_key_len[3], line, value, 3);
}


static int wpa_config_parse_wep_tx_keyidx(struct wpa_ssid *ssid, int line,
					  const char *value)
{
	ssid->wep_tx_keyidx = atoi(value);
	wpa_printf(MSG_MSGDUMP, "wep_tx_keyidx=%d", ssid->wep_tx_keyidx);
	return 0;
}


static int wpa_config_parse_priority(struct wpa_ssid *ssid, int line,
				     const char *value)
{
	ssid->priority = atoi(value);
	wpa_printf(MSG_MSGDUMP, "priority=%d", ssid->priority);
	return 0;
}


static struct wpa_ssid_fields {
	char *name;
	int (*parser)(struct wpa_ssid *ssid, int line, const char *value);
} ssid_fields[] = {
	{ "ssid", wpa_config_parse_ssid },
	{ "scan_ssid", wpa_config_parse_scan_ssid },
	{ "bssid", wpa_config_parse_bssid },
	{ "psk", wpa_config_parse_psk },
	{ "proto", wpa_config_parse_proto },
	{ "key_mgmt", wpa_config_parse_key_mgmt },
	{ "pairwise", wpa_config_parse_pairwise },
	{ "group", wpa_config_parse_group },
	{ "eap", wpa_config_parse_eap },
	{ "identity", wpa_config_parse_identity },
	{ "anonymous_identity", wpa_config_parse_anonymous_identity },
	{ "password", wpa_config_parse_password },
	{ "ca_cert", wpa_config_parse_ca_cert },
	{ "client_cert", wpa_config_parse_client_cert },
	{ "private_key", wpa_config_parse_private_key },
	{ "private_key_passwd", wpa_config_parse_private_key_passwd },
	{ "ca_cert2", wpa_config_parse_ca_cert2 },
	{ "client_cert2", wpa_config_parse_client_cert2 },
	{ "private_key2", wpa_config_parse_private_key2 },
	{ "private_key2_passwd", wpa_config_parse_private_key2_passwd },
	{ "phase1", wpa_config_parse_phase1 },
	{ "phase2", wpa_config_parse_phase2 },
	{ "pcsc", wpa_config_parse_pcsc },
	{ "pin", wpa_config_parse_pin },
	{ "eapol_flags", wpa_config_parse_eapol_flags },
	{ "wep_key0", wpa_config_parse_wep_key0 },
	{ "wep_key1", wpa_config_parse_wep_key1 },
	{ "wep_key2", wpa_config_parse_wep_key2 },
	{ "wep_key3", wpa_config_parse_wep_key3 },
	{ "wep_tx_keyidx", wpa_config_parse_wep_tx_keyidx },
	{ "priority", wpa_config_parse_priority },
};

#define NUM_SSID_FIELDS (sizeof(ssid_fields) / sizeof(ssid_fields[0]))


static struct wpa_ssid * wpa_config_read_network(FILE *f, int *line, int id)
{
	struct wpa_ssid *ssid;
	int errors = 0, i, end = 0;
	char buf[256], *pos, *pos2;

	wpa_printf(MSG_MSGDUMP, "Line: %d - start of a new network block",
		   *line);
	ssid = (struct wpa_ssid *) malloc(sizeof(*ssid));
	if (ssid == NULL)
		return NULL;
	memset(ssid, 0, sizeof(*ssid));
	ssid->id = id;

	ssid->proto = WPA_PROTO_WPA | WPA_PROTO_RSN;
	ssid->pairwise_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP;
	ssid->group_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP |
		WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40;
	ssid->key_mgmt = WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_IEEE8021X;
	ssid->eapol_flags = EAPOL_FLAG_REQUIRE_KEY_UNICAST |
		EAPOL_FLAG_REQUIRE_KEY_BROADCAST;

	while ((pos = wpa_config_get_line(buf, sizeof(buf), f, line))) {
		if (strcmp(pos, "}") == 0) {
			end = 1;
			break;
		}

		pos2 = strchr(pos, '=');
		if (pos2 == NULL) {
			wpa_printf(MSG_ERROR, "Line %d: Invalid SSID line "
				   "'%s'.", *line, pos);
			errors++;
			continue;
		}

		*pos2++ = '\0';
		if (*pos2 == '"') {
			if (strchr(pos2 + 1, '"') == NULL) {
				wpa_printf(MSG_ERROR, "Line %d: invalid "
					   "quotation '%s'.", *line, pos2);
				errors++;
				continue;
			}
		}

		for (i = 0; i < NUM_SSID_FIELDS; i++) {
			if (strcmp(pos, ssid_fields[i].name) == 0) {
				if (ssid_fields[i].parser(ssid, *line, pos2)) {
					wpa_printf(MSG_ERROR, "Line %d: failed"
						   " to parse %s '%s'.",
						   *line, pos, pos2);
					errors++;
				}
				break;
			}
		}
		if (i == NUM_SSID_FIELDS) {
			wpa_printf(MSG_ERROR, "Line %d: unknown network field "
				   "'%s'.", *line, pos);
			errors++;
		}
	}

	if (!end) {
		wpa_printf(MSG_ERROR, "Line %d: network block was not "
			   "terminated properly.", *line);
		errors++;
	}

	if (ssid->passphrase) {
		if (ssid->psk_set) {
			wpa_printf(MSG_ERROR, "Line %d: both PSK and "
				   "passphrase configured.", *line);
			errors++;
		}
		pbkdf2_sha1(ssid->passphrase, ssid->ssid, ssid->ssid_len, 4096,
			    ssid->psk, PMK_LEN);
		wpa_hexdump(MSG_MSGDUMP, "PSK (from passphrase)",
			    ssid->psk, PMK_LEN);
		ssid->psk_set = 1;
	}

	if ((ssid->key_mgmt & WPA_KEY_MGMT_PSK) && !ssid->psk_set) {
		wpa_printf(MSG_ERROR, "Line %d: WPA-PSK accepted for key "
			   "management, but no PSK configured.", *line);
		errors++;
	}

	if (errors) {
		free(ssid);
		ssid = NULL;
	}

	return ssid;
}


static int wpa_config_add_prio_network(struct wpa_config *config,
				       struct wpa_ssid *ssid)
{
	int prio;
	struct wpa_ssid *prev, **nlist;

	for (prio = 0; prio < config->num_prio; prio++) {
		prev = config->pssid[prio];
		if (prev->priority == ssid->priority) {
			while (prev->pnext)
				prev = prev->pnext;
			prev->pnext = ssid;
			return 0;
		}
	}

	/* First network for this priority - add new priority list */
	nlist = realloc(config->pssid,
			(config->num_prio + 1) * sizeof(struct wpa_ssid *));
	if (nlist == NULL)
		return -1;

	for (prio = 0; prio < config->num_prio; prio++) {
		if (nlist[prio]->priority < ssid->priority)
			break;
	}

	memmove(&nlist[prio + 1], &nlist[prio],
		(config->num_prio - prio) * sizeof(struct wpa_ssid *));

	nlist[prio] = ssid;
	config->num_prio++;
	config->pssid = nlist;

	return 0;
}


struct wpa_config * wpa_config_read(const char *config_file)
{
	FILE *f;
	char buf[256], *pos;
	int errors = 0, line = 0;
	struct wpa_ssid *ssid, *tail = NULL, *head = NULL;
	struct wpa_config *config;
	int id = 0, prio;

	config = malloc(sizeof(*config));
	if (config == NULL)
		return NULL;
	memset(config, 0, sizeof(*config));
	config->eapol_version = 1;
	config->ap_scan = 1;
	wpa_printf(MSG_DEBUG, "Reading configuration file '%s'",
		   config_file);
	f = fopen(config_file, "r");
	if (f == NULL) {
		free(config);
		return NULL;
	}

	while ((pos = wpa_config_get_line(buf, sizeof(buf), f, &line))) {
		if (strcmp(pos, "network={") == 0) {
			ssid = wpa_config_read_network(f, &line, id++);
			if (ssid == NULL) {
				wpa_printf(MSG_ERROR, "Line %d: failed to "
					   "parse network block.", line);
				errors++;
				continue;
			}
			if (head == NULL) {
				head = tail = ssid;
			} else {
				tail->next = ssid;
				tail = ssid;
			}
			if (wpa_config_add_prio_network(config, ssid)) {
				wpa_printf(MSG_ERROR, "Line %d: failed to add "
					   "network block to priority list.",
					   line);
				errors++;
				continue;
			}
		} else if (strncmp(pos, "ctrl_interface=", 15) == 0) {
			free(config->ctrl_interface);
			config->ctrl_interface = strdup(pos + 15);
			wpa_printf(MSG_DEBUG, "ctrl_interface='%s'",
				   config->ctrl_interface);
		} else if (strncmp(pos, "ctrl_interface_group=", 21) == 0) {
			struct group *grp;
			char *endp;
			const char *group = pos + 21;

			grp = getgrnam(group);
			if (grp) {
				config->ctrl_interface_gid = grp->gr_gid;
				wpa_printf(MSG_DEBUG, "ctrl_interface_group=%d"
					   " (from group name '%s')",
					   config->ctrl_interface_gid, group);
				continue;
			}

			/* Group name not found - try to parse this as gid */
			config->ctrl_interface_gid = strtol(group, &endp, 10);
			if (*group == '\0' || *endp != '\0') {
				wpa_printf(MSG_DEBUG, "Line %d: Invalid group "
					   "'%s'", line, group);
				errors++;
				continue;
			}
			wpa_printf(MSG_DEBUG, "ctrl_interface_group=%d",
				   config->ctrl_interface_gid);
		} else if (strncmp(pos, "eapol_version=", 14) == 0) {
			config->eapol_version = atoi(pos + 14);
			if (config->eapol_version < 1 ||
			    config->eapol_version > 2) {
				wpa_printf(MSG_ERROR, "Line %d: Invalid EAPOL "
					   "version (%d): '%s'.",
					   line, config->eapol_version, pos);
				errors++;
				continue;
			}
			wpa_printf(MSG_DEBUG, "eapol_version=%d",
				   config->eapol_version);
		} else if (strncmp(pos, "ap_scan=", 8) == 0) {
			config->ap_scan = atoi(pos + 8);
			wpa_printf(MSG_DEBUG, "ap_scan=%d", config->ap_scan);
		} else {
			wpa_printf(MSG_ERROR, "Line %d: Invalid configuration "
				   "line '%s'.", line, pos);
			errors++;
			continue;
		}
	}

	fclose(f);

	config->ssid = head;
	for (prio = 0; prio < config->num_prio; prio++) {
		ssid = config->pssid[prio];
		wpa_printf(MSG_DEBUG, "Priority group %d",
			   ssid->priority);
		while (ssid) {
			wpa_printf(MSG_DEBUG, "   id=%d ssid='%s'",
				   ssid->id,
				   wpa_ssid_txt(ssid->ssid, ssid->ssid_len));
			ssid = ssid->pnext;
		}
	}
	if (errors) {
		wpa_config_free(config);
		config = NULL;
		head = NULL;
	}

	return config;
}


void wpa_config_free(struct wpa_config *config)
{
	struct wpa_ssid *ssid, *prev = NULL;
	ssid = config->ssid;
	while (ssid) {
		prev = ssid;
		ssid = ssid->next;
		free(prev->ssid);
		free(prev->passphrase);
		free(prev->eap_methods);
		free(prev->identity);
		free(prev->anonymous_identity);
		free(prev->password);
		free(prev->ca_cert);
		free(prev->client_cert);
		free(prev->private_key);
		free(prev->private_key_passwd);
		free(prev->ca_cert2);
		free(prev->client_cert2);
		free(prev->private_key2);
		free(prev->private_key2_passwd);
		free(prev->phase1);
		free(prev->phase2);
		free(prev->pcsc);
		free(prev->pin);
		free(prev->otp);
		free(prev->pending_req_otp);
		free(prev);
	}
	free(config->ctrl_interface);
	free(config->pssid);
	free(config);
}


int wpa_config_allowed_eap_method(struct wpa_ssid *ssid, int method)
{
	u8 *pos;

	if (ssid == NULL || ssid->eap_methods == NULL)
		return 1;

	pos = ssid->eap_methods;
	while (*pos != EAP_TYPE_NONE) {
		if (*pos == method)
			return 1;
		pos++;
	}
	return 0;
}
