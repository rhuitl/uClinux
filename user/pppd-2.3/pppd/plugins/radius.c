/*
 * radius.c - RADIUS authentication plugin for pppd
 *
 * (C) Copyright 2001-2002, Philip Craig (philipc@snapgear.com)
 * (C) Copyright 2001, Lineo Inc. (www.lineo.com)
 * (C) Copyright 2002, SnapGear (www.snapgear.com)
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <linux/major.h>
#include <linux/kdev_t.h>

#include <pppd.h>
#include <fsm.h>
#include <ipcp.h>
#include <magic.h>
#include <chap.h>
#ifdef CHAPMS
#include <chap_ms.h>
#include <sha.h>
#ifdef MPPE
#include <mppe.h>
#include <ccp.h>
#endif
#endif

#include "radius.h"
#include "librad.h"

/* State information */
static bool plugin_loaded = 0;
static int accountstart = 0;
static char sessionid[16];
static char radius_reply_message[AUTH_STRING_LEN+1] = "";
static int radius_class_length = -1;
static char radius_class[256];

/* Hooks */
static int (*prev_pap_check_hook) __P((void));
static int (*prev_pap_auth_hook) __P((char *user, char *passwd, char **msgp,
		struct wordlist **paddrs, struct wordlist **popts));
static int (*prev_chap_check_hook) __P((void));
static int (*prev_chap_auth_hook) __P((char *user, u_char *remmd,
		int remmd_len, chap_state *cstate));
static int (*prev_allowed_address_hook) __P((u_int32_t addr));
static void (*prev_ip_choose_hook) __P((u_int32_t *));
static void (*prev_ip_up_hook) __P((void));
static void (*prev_ip_down_hook) __P((void));

/* Options */
static bool use_radius = 0;
static bool use_account = 0;
static u_long radius_server = -1;
static int radius_auth_port = PW_AUTH_UDP_PORT;
static char radius_secret[MAXSECRETLEN] = "";    /* key to encrypt packets */
static u_long nas_ip_address = -1;
static char nas_identifier[AUTH_STRING_LEN+1] = "";
static u_long nas_port_number = -1;
static u_long nas_port_type = -1;
static bool radius_allow_any_ip = 0;
static bool radius_allow_server_ip = 0;
static u_int32_t radius_remote_ip_addr = 0;

/* We calculate this on each auth, using nas_port_number if that is set */
static u_long nas_real_port_number = -1;

static int radius_get_server(char**);
static int radius_nas_ip_address(char**);

static option_t radius_options[] =
{
	{ "radius", o_bool, &use_radius,
	  STR("Enable RADIUS authentication"), 1 },
	{ "radius-accounting", o_bool, &use_account,
	  STR("Enable RADIUS accounting"), 1 },
	{ "radius-server", o_special, radius_get_server,
	  STR("RADIUS server IP address and optional authentication port") },
	{ "radius-secret", o_string, radius_secret,
	  STR("Key used to encrypt RADIUS packets"),
	  OPT_STATIC, NULL, MAXSECRETLEN },
	{ "radius-nas-ip-address", o_special, radius_nas_ip_address,
	  STR("NAS IP address for RADIUS") },
	{ "radius-nas-identifier", o_string, nas_identifier,
	  STR("NAS identifier for RADIUS"), OPT_STATIC, NULL, AUTH_STRING_LEN },
	{ "radius-port-number", o_int, &nas_port_number,
	  STR("Port number for RADIUS") },
	{ "radius-port-type", o_int, &nas_port_type,
	  STR("Port type for RADIUS") },
	{ NULL }
};

static int
radius_get_server(char **argv)
{
	char *p, *endp;
	struct servent *servp;
	struct hostent *hostp;
	struct in_addr addr;

	/* Determine the port */
	p = strchr(*argv, ':');
	if (p != NULL) {
		radius_auth_port = strtoul(p+1, &endp, 10);
		if (*endp) {
			option_error("invalid RADIUS server port '%s'", p+1);
			return 0;
		}
	}
	if (radius_auth_port == 0) {
		servp = getservbyname("radacct", "udp");
		if (servp != NULL) {
			radius_auth_port = ntohs(servp->s_port);
		} else {
			radius_auth_port = PW_AUTH_UDP_PORT;
		}
	}

	/* Remove port if present */
	if (p != NULL)
		*p = 0;
	/* Determine the server IP address */
	if (inet_aton(*argv, &addr) == 0) {
		hostp = gethostbyname(*argv);
		if (hostp == NULL) {
			option_error("invalid RADIUS server '%s'", *argv);
			return 0;
		}
		memcpy((char*)&addr, hostp->h_addr, sizeof(addr));
	}
	if (p != NULL)
		*p = ':';

	radius_server = ntohl(addr.s_addr);
	return 1;
}

static int
radius_nas_ip_address(char **argv)
{
	struct in_addr addr;

	if (inet_aton(*argv, &addr) == 0) {
		option_error("invalid RADIUS NAS IP address '%s'", *argv);
		return 0;
	}

	nas_ip_address = ntohl(addr.s_addr);
	return 1;
}

static int
radius_check(void)
{
	struct stat st;
	int major;
	char *tty;

	if (!use_radius)
		return -1;

	if (radius_server == -1)
		return 0;

	/* Determine reasonable defaults for unspecified options */
	if (nas_port_type == -1) {
		if (using_pty)
			nas_port_type = PW_NAS_PORT_VIRTUAL;
		else if (sync_serial)
			nas_port_type = PW_NAS_PORT_SYNC;
		else {
			nas_port_type = PW_NAS_PORT_ASYNC;

			/* Check if stdin is a pty */
			if (fstat(0, &st) == 0) {
				major = MAJOR(st.st_rdev);
				if (major == PTY_SLAVE_MAJOR || (major >= UNIX98_PTY_SLAVE_MAJOR && major < UNIX98_PTY_SLAVE_MAJOR + UNIX98_PTY_MAJOR_COUNT))
					nas_port_type = PW_NAS_PORT_VIRTUAL;
			}
		}
	}

	/* Default to the supplied option */
	nas_real_port_number = nas_port_number;

	if (nas_real_port_number == -1) {
		if (nas_port_type == PW_NAS_PORT_VIRTUAL)
			nas_real_port_number = ifunit;
		else {
			tty = devnam;
			while (*tty && !isdigit(*tty))
				tty++;
			if (*tty)
				nas_real_port_number = atoi(tty);
		}
	}

	return 1;
}

static int
radius_pap_check(void)
{
	if (!use_radius) {
		if (prev_pap_check_hook)
			return prev_pap_check_hook();
		else
			return -1;
	}

	return radius_check();
}

static int
radius_chap_check(void)
{
	if (!use_radius) {
		if (prev_chap_check_hook)
			return prev_chap_check_hook();
		else
			return -1;
	}

	return radius_check();
}

static int radius_check_integer_length(struct radius_attrib *attrib)
{
	if (attrib->length != 4) {
		error("RADIUS: invalid integer attribute length '%d'",
				attrib->length);
		return 0;
	}
	else {
		return 1;
	}
}

static int
radius_auth(struct radius_attrib **attriblist, chap_state *cstate)
{
	int ret;
	struct radius_attrib *recvattriblist;
	struct radius_attrib *attrib;
#ifdef CHAPMS
	int ms_chap2_success = 0;
#endif
#ifdef MPPE
	int mppe_send_key = 0, mppe_recv_key = 0, mppe_policy = 0, mppe_types = 0;
#endif

	if (nas_ip_address != -1) {
		if (!radius_add_attrib(
				attriblist, PW_VENDOR_NONE, PW_NAS_IP_ADDRESS,
				nas_ip_address, NULL, 0)) {
			return 0;
		}
	}
	else if (nas_identifier[0]) {
		if (!radius_add_attrib(
				attriblist, PW_VENDOR_NONE, PW_NAS_IDENTIFIER,
				0, nas_identifier, strlen(nas_identifier))) {
			return 0;
		}
	}

	if (nas_real_port_number != -1) {
		if (!radius_add_attrib(
				attriblist, PW_VENDOR_NONE, PW_NAS_PORT_ID,
				nas_real_port_number, NULL, 0)) {
			return 0;
		}
	}

	if (nas_port_type != -1) {
		if (!radius_add_attrib(
				attriblist, PW_VENDOR_NONE, PW_NAS_PORT_TYPE,
				nas_port_type, NULL, 0)) {
			return 0;
		}
	}

	if (!radius_add_attrib(
			attriblist, PW_VENDOR_NONE, PW_SERVICE_TYPE,
			PW_FRAMED_USER, NULL, 0)) {
		return 0;
	}

	if (!radius_add_attrib(
			attriblist, PW_VENDOR_NONE, PW_FRAMED_PROTOCOL,
			PW_PPP, NULL, 0)) {
		return 0;
	}

	if (ipcp_wantoptions[0].hisaddr) {
		if (!radius_add_attrib(
				attriblist, PW_VENDOR_NONE,
				PW_FRAMED_IP_ADDRESS,
				ntohl(ipcp_wantoptions[0].hisaddr), NULL, 0)) {
			return 0;
		}
	}

	recvattriblist = NULL;
	ret = radius_send_access_request(
			radius_server, radius_auth_port, radius_secret,
			*attriblist, &recvattriblist);
	if (ret < 0) {
		error("RADIUS: server failed");
		ret = 0;
	}
	else if (ret == PW_AUTHENTICATION_ACK) {
		ret = 1; /* Default to success unless an attribute makes us fail */
		for (attrib=recvattriblist; ret && attrib!=NULL; attrib=attrib->next) {
			if (attrib->vendor == PW_VENDOR_NONE) {
				switch (attrib->type) {
				case PW_SERVICE_TYPE:
					if (ntohl(attrib->u.value) != PW_FRAMED_USER) {
						error("RADIUS: service type '%d' is not framed", ntohl(attrib->u.value));
						ret = 0;
					}
					break;

				case PW_FRAMED_PROTOCOL:
					if (ntohl(attrib->u.value) != PW_PPP) {
						error("RADIUS: framed protocol '%d' is not ppp", ntohl(attrib->u.value));
						ret = 0;
					}
					break;

				case PW_FRAMED_IP_ADDRESS:
					if (attrib->u.value == htonl(0xffffffff)) {
						radius_allow_any_ip = 1;
					}
					else if (attrib->u.value == htonl(0xfffffffe)) {
						radius_allow_server_ip = 1;
					}
					else {
						radius_remote_ip_addr = attrib->u.value;
					}
					break;

				case PW_FRAMED_IP_NETMASK:
					if (attrib->u.value && attrib->u.value != 0xffffffff) {
						netmask = attrib->u.value;
					}
					break;

				case PW_FRAMED_COMPRESSION:
					if (ntohl(attrib->u.value) == PW_NONE) {
						ipcp_wantoptions[0].neg_vj = 0;
						ipcp_allowoptions[0].neg_vj = 0;
					}
					else if (ntohl(attrib->u.value) == PW_VAN_JACOBSEN_TCP_IP) {
						ipcp_wantoptions[0].neg_vj = 1;
						ipcp_allowoptions[0].neg_vj = 1;
					}
					break;

				case PW_REPLY_MESSAGE:
					strncpy(radius_reply_message,attrib->u.string,AUTH_STRING_LEN);
					radius_reply_message[AUTH_STRING_LEN] = 0;
					notice(radius_reply_message);
					break;

#if 0
				case PW_FRAMED_ROUTE:
					/* XXX: store route for adding/removing in ip-up/ip-down */
					break;

				case PW_FRAMED_MTU:
					/* XXX: set the MTU? */
					break;
#endif

				case PW_IDLE_TIMEOUT:
					if (attrib->u.value != 0) {
						idle_time_limit = ntohl(attrib->u.value);
					}
					break;

				case PW_SESSION_TIMEOUT:
					if (attrib->u.value != 0) {
						maxconnect = ntohl(attrib->u.value);
					}
					break;

				case PW_CLASS:
					radius_class_length = attrib->length;
					if (radius_class_length > sizeof(radius_class))
						radius_class_length = sizeof(radius_class);
					memcpy(radius_class, attrib->u.string, radius_class_length);
					break;

				default:
					notice("RADIUS: ignoring unsupported attribute %d",
							attrib->type);
					break;
				}
			}
#ifdef CHAPMS
			else if (attrib->vendor == PW_VENDOR_MICROSOFT) {
				switch (attrib->type) {
				case PW_MS_CHAP2_SUCCESS:
					if (ms_chap2_success) {
						error("RADIUS: duplicate MS_CHAP2_SUCCESS");
						ret = 0;
						break;
					}
					ms_chap2_success = 1;

					if (!cstate || (cstate->chal_type != CHAP_MICROSOFT_V2)) {
						error("RADIUS: unexpected MS_CHAP2_SUCCESS");
						ret = 0;
						break;
					}

					if (attrib->length != 43) {
						error("RADIUS: invalid MS_CHAP2_SUCCESS length '%d'", attrib->length);
						ret = 0;
						break;
					}
					if (strncmp(attrib->u.string+1, "S=", 2)) {
						error("RADIUS: invalid MS_CHAP2_SUCCESS");
						ret = 0;
						break;
					}
					memcpy(cstate->response, attrib->u.string+1, attrib->length-1);
					cstate->response[attrib->length-1] = '\0';
					break;

#ifdef MPPE
				case PW_MS_CHAP_MPPE_KEYS: {
					unsigned char Digest[SHA_DIGEST_LENGTH];
					SHA_CTX Context;
    
					if (!cstate || (cstate->chal_type != CHAP_MICROSOFT)) {
						error("RADIUS: unexpected MS_CHAP_MPPE_KEYS");
						ret = 0;
						break;
					}

					if (attrib->length != 32) {
						error("RADIUS: invalid MS_CHAP_MPPE_KEYS length '%d'", attrib->length);
						ret = 0;
						break;
					}

					memcpy(mppe_master_send_key_40, attrib->u.string, 8);
					memcpy(mppe_master_recv_key_40, attrib->u.string, 8);

					SHA1_Init(&Context);
					SHA1_Update(&Context, attrib->u.string + 8, 16);
					SHA1_Update(&Context, attrib->u.string + 8, 16);
					SHA1_Update(&Context, cstate->challenge, 8);
					SHA1_Final(Digest, &Context);

					memcpy(mppe_master_send_key_128, Digest, 16);
					memcpy(mppe_master_recv_key_128, Digest, 16);
					mppe_send_key = mppe_recv_key = 1;
					break;
				}

				case PW_MS_MPPE_SEND_KEY:
					if (!cstate || (cstate->chal_type != CHAP_MICROSOFT_V2)) {
						error("RADIUS: unexpected MS_MPPE_SEND_KEY");
						ret = 0;
						break;
					}
					if (attrib->length != 34) {
						error("RADIUS: invalid MS_MPPE_SEND_KEY length '%d'", attrib->length);
						ret = 0;
						break;
					}
					if ((attrib->u.string[0] & 0x80) == 0) {
						error("RADIUS: invalid MS_MPPE_SEND_KEY salt '%02x%02x'", (unsigned char)attrib->u.string[0], (unsigned char)attrib->u.string[1]);
						ret = 0;
						break;
					}
					if (attrib->u.string[2] != 16) {
						error("RADIUS: invalid MS_MPPE_SEND_KEY keylength '%d'", attrib->u.string[2]);
						ret = 0;
						break;
					}
					memcpy(mppe_master_send_key_128, attrib->u.string+3, 16);
					memcpy(mppe_master_send_key_40, attrib->u.string+3, 8);
					mppe_send_key = 1;
					break;

				case PW_MS_MPPE_RECV_KEY:
					if (!cstate || (cstate->chal_type != CHAP_MICROSOFT_V2)) {
						error("RADIUS: unexpected MS_MPPE_RECV_KEY");
						ret = 0;
						break;
					}
					if (attrib->length != 34) {
						error("RADIUS: invalid MS_MPPE_RECV_KEY length '%d'", attrib->length);
						ret = 0;
						break;
					}
					if ((attrib->u.string[0] & 0x80) == 0) {
						error("RADIUS: invalid MS_MPPE_RECV_KEY salt '%02x%02x'", (unsigned char)attrib->u.string[0], (unsigned char)attrib->u.string[1]);
						ret = 0;
						break;
					}
					if (attrib->u.string[2] != 16) {
						error("RADIUS: invalid MS_MPPE_RECV_KEY keylength '%d'", attrib->u.string[2]);
						ret = 0;
						break;
					}
					memcpy(mppe_master_recv_key_128, attrib->u.string+3, 16);
					memcpy(mppe_master_recv_key_40, attrib->u.string+3, 8);
					mppe_recv_key = 1;
					break;

				case PW_MS_MPPE_ENCRYPTION_POLICY:
					if (!radius_check_integer_length(attrib)) {
						ret = 0;
						break;
					}

					if (attrib->u.value == htonl(1)) {
						/* Encryption allowed */
						ccp_allowoptions[0].mppe = 1;
						ccp_wantoptions[0].mppe = 0;
						mppe_policy = 1;
					}
					else if (attrib->u.value == htonl(2)) {
						/* Encryption required */
						/* XXX: current version of ppd doesn't support
						 * requiring encryption. */
						ccp_allowoptions[0].mppe = ccp_wantoptions[0].mppe = 1;
						mppe_policy = 1;
					}
					break;

				case PW_MS_MPPE_ENCRYPTION_TYPES:
					if (!radius_check_integer_length(attrib)) {
						ret = 0;
						break;
					}

					ccp_allowoptions[0].mppe_40
						= ccp_wantoptions[0].mppe_40
						= (attrib->u.value & htonl(2)) ? 1 : 0;
					ccp_allowoptions[0].mppe_128
						= ccp_wantoptions[0].mppe_128
						= (attrib->u.value & htonl(4)) ? 1 : 0;
					mppe_types = 1;
					break;
#endif /* MPPE */

#if 0
				case PW_MS_PRIMARY_DNS_SERVER:
				case PW_MS_SECONDARY_DNS_SERVER:
				case PW_MS_PRIMARY_NBNS_SERVER:
				case PW_MS_SECONDARY_NBNS_SERVER:
					break;
#endif

				default:
					notice("RADIUS: ignoring Microsoft attribute %d",
							attrib->type);
					break;
				}
			}
#endif /* CHAPMS */
			else {
				notice("RADIUS: ignoring vendor %d attribute %d",
						attrib->vendor, attrib->type);
			}
		}
#ifdef CHAPMS
		if (ret && cstate && (cstate->chal_type == CHAP_MICROSOFT_V2)
				&& !ms_chap2_success) {
			error("RADIUS: MSCHAPv2 success attribute not found");
			ret = 0;
		}
#endif
#ifdef MPPE
		if (mppe_send_key && mppe_recv_key) {
			if (mppe_policy && mppe_types) {
				mppe_allowed = 1;
			} else if (!mppe_policy) {
				mppe_allowed = 1;
			}
		}
#endif
	}
	else if (ret == PW_AUTHENTICATION_REJECT) {
		for (attrib=recvattriblist; attrib!=NULL; attrib=attrib->next) {
			if (attrib->vendor == PW_VENDOR_NONE
					&& attrib->type == PW_REPLY_MESSAGE) {
				strncpy(radius_reply_message,attrib->u.string,AUTH_STRING_LEN);
				radius_reply_message[AUTH_STRING_LEN] = 0;
				error("%s", radius_reply_message);
			}
		}
		ret = 0;
	}
	else if (ret == PW_ACCESS_CHALLENGE) {
		error("RADIUS: server sent unexpected CHAP challenge");
		ret = 0;
	}
	else {
		error("RADIUS: server sent unexpected response '%d'", ret);
		ret = 0;
	}

	radius_free_attrib(recvattriblist);

	return ret;
}

/* Authenticate/authorize */
static int
radius_pap_auth(char *t_user, char *t_passwd, char **t_msgp,
		struct wordlist **t_paddrs, struct wordlist **t_popts)
{
	int ret;
	struct radius_attrib *attriblist;
    
	if (!use_radius) {
		if (prev_pap_auth_hook)
			return prev_pap_auth_hook(t_user, t_passwd, t_msgp,
					t_paddrs, t_popts);
		else
			return -1;
	}

	*t_msgp = "Login failed";
	if (radius_server == -1) {
		error("RADIUS: server not found");
		return 0;
	}

	attriblist = NULL;

	if (!radius_add_attrib(
			&attriblist, PW_VENDOR_NONE, PW_USER_NAME,
			0, t_user, strlen(t_user))) {
		radius_free_attrib(attriblist);
		return 0;
	}

	if (!radius_add_attrib(
			&attriblist, PW_VENDOR_NONE, PW_PASSWORD,
			0, t_passwd, strlen(t_passwd))) {
		radius_free_attrib(attriblist);
		return 0;
	}

	ret = radius_auth(&attriblist, NULL);
	if (ret > 0)
		*t_msgp = "Login ok";

	radius_free_attrib(attriblist);

	return ret;
}

static int
radius_chap_auth(char *user, u_char *remmd, int remmd_len, chap_state *cstate)
{
	struct radius_attrib *attriblist;
	u_char chap_password[MAX_RESPONSE_LENGTH+1], *p;
	int code = CHAP_SUCCESS;
    
	if (!use_radius) {
		if (prev_chap_auth_hook)
			return prev_chap_auth_hook(user, remmd, remmd_len, cstate);
		else
			return -1;
	}

	if (radius_server == -1) {
		error("RADIUS: server not found");
		return CHAP_FAILURE;
	}

	attriblist = NULL;

	if (!radius_add_attrib(
			&attriblist, PW_VENDOR_NONE, PW_USER_NAME,
			0, user, strlen(user)))
		goto error;

	switch (cstate->chal_type) {
	case CHAP_DIGEST_MD5:
		if (remmd_len != MD5_SIGNATURE_SIZE) {
			error("RADIUS: invalid CHAP response length '%d'",
					remmd_len);
			goto error;
		}

		if (!radius_add_attrib(
				&attriblist, PW_VENDOR_NONE, PW_CHAP_CHALLENGE,
				0, cstate->challenge, cstate->chal_len))
			goto error;

		p = chap_password;
		*p++ = cstate->chal_id;
		memcpy(p, remmd, remmd_len);
		if (!radius_add_attrib(
				&attriblist, PW_VENDOR_NONE, PW_CHAP_PASSWORD,
				0, chap_password, remmd_len+1))
			goto error;
		break;

#ifdef CHAPMS
	case CHAP_MICROSOFT: {
		MS_ChapResponse *response = (MS_ChapResponse *)remmd;

		if (remmd_len != MS_CHAP_RESPONSE_LEN) {
			error("RADIUS: invalid MSCHAP response length '%d'",
					remmd_len);
			goto error;
		}

		if (!radius_add_attrib(
				&attriblist, PW_VENDOR_MICROSOFT, PW_MS_CHAP_CHALLENGE,
				0, cstate->challenge, cstate->chal_len))
			goto error;

		p = chap_password;
		*p++ = cstate->chal_id;
		*p++ = response->UseNT;
		memcpy(p, response->LANManResp, sizeof(response->LANManResp));
		p += sizeof(response->LANManResp);
		memcpy(p, response->NTResp, sizeof(response->NTResp));
		p += sizeof(response->NTResp);

		if (!radius_add_attrib(
				&attriblist, PW_VENDOR_MICROSOFT, PW_MS_CHAP_RESPONSE,
				0, chap_password, p-chap_password))
			goto error;
		break;
	}

	case CHAP_MICROSOFT_V2: {
		MS_ChapResponse_v2 *response = (MS_ChapResponse_v2 *)remmd;

		if (remmd_len != MS_CHAP_RESPONSE_LEN) {
			error("RADIUS: invalid MSCHAPv2 response length '%d'",
					remmd_len);
			goto error;
		}

		if (!radius_add_attrib(
				&attriblist, PW_VENDOR_MICROSOFT, PW_MS_CHAP_CHALLENGE,
				0, cstate->challenge, cstate->chal_len))
			goto error;

		p = chap_password;
		*p++ = cstate->chal_id;
		*p++ = 0;
		memcpy(p, response->PeerChallenge, sizeof(response->PeerChallenge));
		p += sizeof(response->PeerChallenge);
		memset(p, 0, sizeof(response->Reserved));
		p += sizeof(response->Reserved);
		memcpy(p, response->NTResp, sizeof(response->NTResp));
		p += sizeof(response->NTResp);

		if (!radius_add_attrib(
				&attriblist, PW_VENDOR_MICROSOFT, PW_MS_CHAP2_RESPONSE,
				0, chap_password, p-chap_password)) {
			goto error;
		}
		code = CHAP_SUCCESS_R;
		break;
	}
#endif

	default:
		error("RADIUS: unsupported challenge type '%d'",
				cstate->chal_type);
		goto error;
	}

	if (radius_auth(&attriblist, cstate) == 1) {
		radius_free_attrib(attriblist);
		return code;
	}

 error:
	radius_free_attrib(attriblist);
	return CHAP_FAILURE;
}

static void
radius_ip_choose(u_int32_t *addrp)
{
	if (use_radius && radius_remote_ip_addr) {
		*addrp = radius_remote_ip_addr;
	}
}

static int
radius_allowed_address(u_int32_t addr)
{
	ipcp_options *wo = &ipcp_wantoptions[0];

	if (!use_radius) {
		if (prev_allowed_address_hook)
			return prev_allowed_address_hook(addr);
		else
			return -1;
	}

	if (radius_allow_any_ip) {
		return 1;
	}
	else if (radius_allow_server_ip) {
		if (wo->hisaddr && addr == wo->hisaddr)
			return 1;
		else
			return 0;
	}
	else if (radius_remote_ip_addr) {
		if (addr == radius_remote_ip_addr)
			return 1;
		else
			return 0;
	} else if (wo->accept_remote) {
		return 1;
	} else if (wo->hisaddr && addr == wo->hisaddr) {
		return 1;
	}

	return 0;
}

static int
radius_common_account_attrib(struct radius_attrib **attriblist)
{
	if (!radius_add_attrib(
			attriblist, PW_VENDOR_NONE, PW_USER_NAME,
			0, peer_authname, strlen(peer_authname)))
		return 0;

	/* Although the RFC states that one of these two MUST be present,
	 * the cistron radiusd uses the source address of the packet if
	 * the PW_NAS_IP_ADDRESS is not specified. */
	if (nas_ip_address != -1) {
		if (!radius_add_attrib(
				attriblist, PW_VENDOR_NONE, PW_NAS_IP_ADDRESS,
				nas_ip_address, NULL, 0))
			return 0;
	}
	else if (nas_identifier[0]) {
		if (!radius_add_attrib(
				attriblist, PW_VENDOR_NONE, PW_NAS_IDENTIFIER,
				0, nas_identifier, strlen(nas_identifier)))
			return 0;
	}

	if (nas_real_port_number != -1) {
		if (!radius_add_attrib(
				attriblist, PW_VENDOR_NONE, PW_NAS_PORT_ID,
				nas_real_port_number, NULL, 0))
			return 0;
	}
	
	if (nas_port_type != -1) {
		if (!radius_add_attrib(
				attriblist, PW_VENDOR_NONE, PW_NAS_PORT_TYPE,
				nas_port_type, NULL, 0))
			return 0;
	}

	if (!radius_add_attrib(
			attriblist, PW_VENDOR_NONE, PW_SERVICE_TYPE,
			PW_FRAMED_USER, NULL, 0))
		return 0;

	if (!radius_add_attrib(
			attriblist, PW_VENDOR_NONE, PW_FRAMED_PROTOCOL,
			PW_PPP, NULL, 0))
		return 0;

	/* ntohl here because hisaddr is already network byte order,
	 * radius_add_attrib will convert back to network byte order again */
	if (!radius_add_attrib(
			attriblist, PW_VENDOR_NONE, PW_FRAMED_IP_ADDRESS,
			ntohl(ipcp_hisoptions->hisaddr), NULL, 0))
		return 0;

	if (!radius_add_attrib(
			attriblist, PW_VENDOR_NONE, PW_FRAMED_COMPRESSION,
			ipcp_gotoptions[0].neg_vj ? PW_VAN_JACOBSEN_TCP_IP : PW_NONE,
			NULL, 0))
		return 0;

	if (radius_class_length >= 0) {
		if (!radius_add_attrib(
				attriblist, PW_VENDOR_NONE, PW_CLASS,
				0, radius_class, radius_class_length))
			return 0;
	}

	return 1;
}

static void
radius_ip_up(void)
{
	struct radius_attrib *attriblist, *recvattriblist;
	int ret;

	if (prev_ip_up_hook) {
		prev_ip_up_hook();
	}

	if (use_account) {
		if (radius_server == -1)
			return;

		attriblist = NULL;
		recvattriblist = NULL;
	
		if (!radius_add_attrib(
				&attriblist, PW_VENDOR_NONE, PW_ACCT_STATUS_TYPE,
				PW_STATUS_START, NULL, 0)) {
			radius_free_attrib(attriblist);
			return;
		}

		sprintf(sessionid, "%x", radius_sessionid());
		if (!radius_add_attrib(
				&attriblist, PW_VENDOR_NONE, PW_ACCT_SESSION_ID,
				0, sessionid, strlen(sessionid))) {
			radius_free_attrib(attriblist);
			return;
		}

		if (!radius_common_account_attrib(&attriblist)) {
			radius_free_attrib(attriblist);
			return;
		}

		ret = radius_send_account_request(
				radius_server, radius_auth_port+1, radius_secret,
				attriblist, &recvattriblist);

		radius_free_attrib(attriblist);
		radius_free_attrib(recvattriblist);

		if (ret >= 0) {
			accountstart = 1;
		}
	}
}

static void
radius_ip_down(void)
{
	struct radius_attrib *attriblist, *recvattriblist;

	if (prev_ip_down_hook) {
		prev_ip_down_hook();
	}

	/* Put in the accountstart check here since this hook
	 * also gets called if an IP address could not be
	 * negotiated. */
	if (use_account && accountstart) {
		accountstart = 0;

		if (radius_server == -1)
			return;

		attriblist = NULL;
		recvattriblist = NULL;
	
		if (!radius_add_attrib(
				&attriblist, PW_VENDOR_NONE, PW_ACCT_STATUS_TYPE,
				PW_STATUS_STOP, NULL, 0)) {
			radius_free_attrib(attriblist);
			return;
		}

		if (!radius_add_attrib(
				&attriblist, PW_VENDOR_NONE, PW_ACCT_SESSION_ID,
				0, sessionid, strlen(sessionid))) {
			radius_free_attrib(attriblist);
			return;
		}

		if (!radius_common_account_attrib(&attriblist)) {
			radius_free_attrib(attriblist);
			return;
		}

		if (link_stats_valid) {
			if (!radius_add_attrib(
					&attriblist, PW_VENDOR_NONE, PW_ACCT_INPUT_OCTETS,
					link_stats.bytes_in, NULL, 0)) {
				radius_free_attrib(attriblist);
				return;
			}

			if (!radius_add_attrib(
					&attriblist, PW_VENDOR_NONE, PW_ACCT_OUTPUT_OCTETS,
					link_stats.bytes_out, NULL, 0)) {
				radius_free_attrib(attriblist);
				return;
			}

			if (!radius_add_attrib(
					&attriblist, PW_VENDOR_NONE, PW_ACCT_SESSION_TIME,
					link_connect_time, NULL, 0)) {
				radius_free_attrib(attriblist);
				return;
			}

		}

		radius_send_account_request(
				radius_server, radius_auth_port+1, radius_secret,
				attriblist, &recvattriblist);

		radius_free_attrib(attriblist);
		radius_free_attrib(recvattriblist);
	}
}

void
#ifdef EMBED
radius_plugin_init(void)
#else
	 plugin_init(void)
#endif
{
	if (!plugin_loaded) {
		plugin_loaded = 1;

		magic_init();
	
		/* install pppd hooks */
		add_options(radius_options);
	
		prev_pap_check_hook = pap_check_hook;
		pap_check_hook = radius_pap_check;
	
		prev_pap_auth_hook = pap_auth_hook;
		pap_auth_hook = radius_pap_auth;
	
		prev_chap_check_hook = chap_check_hook;
		chap_check_hook = radius_chap_check;

		prev_chap_auth_hook = chap_auth_hook;
		chap_auth_hook = radius_chap_auth;

		prev_allowed_address_hook = allowed_address_hook;
		allowed_address_hook = radius_allowed_address;
	
		prev_ip_choose_hook = ip_choose_hook;
		ip_choose_hook = radius_ip_choose;

		prev_ip_up_hook = ip_up_hook;
		ip_up_hook = radius_ip_up;
	
		prev_ip_down_hook = ip_down_hook;
		ip_down_hook = radius_ip_down;
	}
}
