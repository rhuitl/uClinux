/*
 * Wireless LAN card diagnostics tool for Host AP kernel driver
 * Copyright (c) 2002-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>

#include "util.h"


static int diag_show_summary(const char *dev)
{
	char buf[PRISM2_HOSTAPD_MAX_BUF_SIZE];
	struct prism2_hostapd_param *param;
	int res;

	printf("Host AP driver diagnostics information for '%s'\n\n", dev);

	param = (struct prism2_hostapd_param *) buf;

	res = hostapd_get_rid(dev, param, HFA384X_RID_NICID, 1);
	if (res == EPERM) {
		printf("hostap_diag requires root privileges\n");
		return -1;
	}
	if (res == ENODATA) {
		printf("NICID read did not return any data.\n");
	} else if (res) {
		printf("Could not communicate with the kernel driver.\n");
		return -1;
	}

	if (res == 0)
		hostap_show_nicid(param->u.rid.data, param->u.rid.len);

	if (!hostapd_get_rid(dev, param, HFA384X_RID_PRIID, 1))
		hostap_show_priid(param->u.rid.data, param->u.rid.len);

	if (!hostapd_get_rid(dev, param, HFA384X_RID_STAID, 1))
		hostap_show_staid(param->u.rid.data, param->u.rid.len);

	return 0;
}


#define RID(n,t) { HFA384X_RID_##n, #n, t }
enum { RID_HEXDUMP, RID_WORD, RID_HWADDR, RID_STRING, RID_COMPID,
       RID_SUPRANGE, RID_HEXSTRING, RID_CIS };

static struct {
	u16 rid;
	char *name;
	int type;
} rid_table[] = {
	RID(CNFPORTTYPE, RID_WORD),
	RID(CNFOWNMACADDR, RID_HWADDR),
	RID(CNFDESIREDSSID, RID_STRING),
	RID(CNFOWNCHANNEL, RID_WORD),
	RID(CNFOWNSSID, RID_STRING),
	RID(CNFOWNATIMWINDOW, RID_WORD),
	RID(CNFSYSTEMSCALE, RID_WORD),
	RID(CNFMAXDATALEN, RID_WORD),
	RID(CNFWDSADDRESS, RID_HWADDR),
	RID(CNFPMENABLED, RID_WORD),
	RID(CNFPMEPS, RID_WORD),
	RID(CNFMULTICASTRECEIVE, RID_WORD),
	RID(CNFMAXSLEEPDURATION, RID_WORD),
	RID(CNFPMHOLDOVERDURATION, RID_WORD),
	RID(CNFOWNNAME, RID_STRING),
	RID(CNFOWNDTIMPERIOD, RID_WORD),
	RID(CNFWDSADDRESS1, RID_HWADDR),
	RID(CNFWDSADDRESS2, RID_HWADDR),
	RID(CNFWDSADDRESS3, RID_HWADDR),
	RID(CNFWDSADDRESS4, RID_HWADDR),
	RID(CNFWDSADDRESS5, RID_HWADDR),
	RID(CNFWDSADDRESS6, RID_HWADDR),
	RID(CNFMULTICASTPMBUFFERING, RID_WORD),
	RID(UNKNOWN1, RID_WORD),
	RID(UNKNOWN2, RID_WORD),
	RID(CNFWEPDEFAULTKEYID, RID_WORD),
	RID(CNFDEFAULTKEY0, RID_HEXDUMP),
	RID(CNFDEFAULTKEY1, RID_HEXDUMP),
	RID(CNFDEFAULTKEY2, RID_HEXDUMP),
	RID(CNFDEFAULTKEY3, RID_HEXDUMP),
	RID(CNFWEPFLAGS, RID_HEXDUMP),
	RID(CNFWEPKEYMAPPINGTABLE, RID_HEXDUMP),
	RID(CNFAUTHENTICATION, RID_WORD),
	RID(CNFMAXASSOCSTA, RID_WORD),
	RID(CNFTXCONTROL, RID_WORD),
	RID(CNFROAMINGMODE, RID_WORD),
	RID(CNFHOSTAUTHENTICATION, RID_WORD),
	RID(CNFRCVCRCERROR, RID_WORD),
	RID(CNFMMLIFE, RID_WORD),
	RID(CNFALTRETRYCOUNT, RID_WORD),
	RID(CNFBEACONINT, RID_WORD),
	RID(CNFAPPCFINFO, RID_HEXDUMP),
	RID(CNFSTAPCFINFO, RID_HEXDUMP),
	RID(CNFPRIORITYQUSAGE, RID_HEXDUMP),
	RID(CNFTIMCTRL, RID_WORD),
	RID(UNKNOWN3, RID_HEXDUMP),
	RID(CNFTHIRTY2TALLY, RID_WORD),
	RID(CNFENHSECURITY, RID_WORD),
	RID(CNFDBMADJUST, RID_WORD),
	RID(GENERICELEMENT, RID_HEXDUMP),
	RID(PROPAGATIONDELAY, RID_WORD),
	RID(GROUPADDRESSES, RID_HEXDUMP),
	RID(CREATEIBSS, RID_WORD),
	RID(FRAGMENTATIONTHRESHOLD, RID_WORD),
	RID(RTSTHRESHOLD, RID_WORD),
	RID(TXRATECONTROL, RID_WORD),
	RID(PROMISCUOUSMODE, RID_WORD),
	RID(FRAGMENTATIONTHRESHOLD0, RID_WORD),
	RID(FRAGMENTATIONTHRESHOLD1, RID_WORD),
	RID(FRAGMENTATIONTHRESHOLD2, RID_WORD),
	RID(FRAGMENTATIONTHRESHOLD3, RID_WORD),
	RID(FRAGMENTATIONTHRESHOLD4, RID_WORD),
	RID(FRAGMENTATIONTHRESHOLD5, RID_WORD),
	RID(FRAGMENTATIONTHRESHOLD6, RID_WORD),
	RID(RTSTHRESHOLD0, RID_WORD),
	RID(RTSTHRESHOLD1, RID_WORD),
	RID(RTSTHRESHOLD2, RID_WORD),
	RID(RTSTHRESHOLD3, RID_WORD),
	RID(RTSTHRESHOLD4, RID_WORD),
	RID(RTSTHRESHOLD5, RID_WORD),
	RID(RTSTHRESHOLD6, RID_WORD),
	RID(TXRATECONTROL0, RID_WORD),
	RID(TXRATECONTROL1, RID_WORD),
	RID(TXRATECONTROL2, RID_WORD),
	RID(TXRATECONTROL3, RID_WORD),
	RID(TXRATECONTROL4, RID_WORD),
	RID(TXRATECONTROL5, RID_WORD),
	RID(TXRATECONTROL6, RID_WORD),
	RID(CNFSHORTPREAMBLE, RID_WORD),
	RID(CNFEXCLUDELONGPREAMBLE, RID_WORD),
	RID(CNFAUTHENTICATIONRSPTO, RID_WORD),
	RID(CNFBASICRATES, RID_HEXDUMP),
	RID(CNFSUPPORTEDRATES, RID_HEXDUMP),
	RID(CNFFALLBACKCTRL, RID_WORD),
	RID(WEPKEYDISABLE, RID_WORD),
	RID(WEPKEYMAPINDEX, RID_HEXDUMP),
	RID(BROADCASTKEYID, RID_HEXDUMP),
	RID(ENTSECFLAGEYID, RID_HEXDUMP),
	RID(CNFPASSIVESCANCTRL, RID_WORD),

	RID(SSNHANDLINGMODE, RID_WORD),
	RID(MDCCONTROL, RID_WORD),
	RID(MDCCOUNTRY, RID_HEXDUMP),
	RID(TXPOWERMAX, RID_WORD),
	RID(CNFLFOENABLED, RID_WORD),
	RID(CAPINFO, RID_WORD),
	RID(LISTENINTERVAL, RID_WORD),
	RID(SW_ANT_DIV, RID_HEXDUMP),
	RID(LED_CTRL, RID_HEXDUMP),
	RID(HFODELAY, RID_WORD),
	RID(DISALLOWEDBSSID, RID_HEXDUMP),
	RID(TICKTIME, RID_WORD),
	RID(SCANREQUEST, RID_HEXDUMP),
	RID(JOINREQUEST, RID_HEXDUMP),
	RID(AUTHENTICATESTATION, RID_HEXDUMP),
	RID(CHANNELINFOREQUEST, RID_HEXDUMP),
	RID(HOSTSCAN, RID_HEXDUMP),

	RID(MAXLOADTIME, RID_WORD),
	RID(DOWNLOADBUFFER, RID_HEXDUMP),
	RID(PRIID, RID_COMPID),
	RID(PRISUPRANGE, RID_SUPRANGE),
	RID(CFIACTRANGES, RID_SUPRANGE),
	RID(NICSERNUM, RID_STRING),
	RID(NICID, RID_COMPID),
	RID(MFISUPRANGE, RID_SUPRANGE),
	RID(CFISUPRANGE, RID_SUPRANGE),
	RID(CHANNELLIST, RID_HEXDUMP),
	RID(REGULATORYDOMAINS, RID_STRING),
	RID(TEMPTYPE, RID_WORD),
	RID(CIS, RID_CIS),
	RID(STAID, RID_COMPID),
	RID(STASUPRANGE, RID_SUPRANGE),
	RID(MFIACTRANGES, RID_SUPRANGE),
	RID(CFIACTRANGES2, RID_SUPRANGE),
	RID(PRODUCTNAME, RID_STRING),
	RID(PORTSTATUS, RID_WORD),
	RID(CURRENTSSID, RID_STRING),
	RID(CURRENTBSSID, RID_HWADDR),
	RID(COMMSQUALITY, RID_HEXDUMP),
	RID(CURRENTTXRATE, RID_WORD),
	RID(CURRENTBEACONINTERVAL, RID_WORD),
	RID(CURRENTSCALETHRESHOLDS, RID_HEXDUMP),
	RID(PROTOCOLRSPTIME, RID_WORD),
	RID(SHORTRETRYLIMIT, RID_WORD),
	RID(LONGRETRYLIMIT, RID_WORD),
	RID(MAXTRANSMITLIFETIME, RID_WORD),
	RID(MAXRECEIVELIFETIME, RID_WORD),
	RID(CFPOLLABLE, RID_WORD),
	RID(AUTHENTICATIONALGORITHMS, RID_HEXDUMP),
	RID(PRIVACYOPTIONIMPLEMENTED, RID_WORD),
	RID(DBMCOMMSQUALITY, RID_HEXDUMP),
	RID(CURRENTTXRATE1, RID_WORD),
	RID(CURRENTTXRATE2, RID_WORD),
	RID(CURRENTTXRATE3, RID_WORD),
	RID(CURRENTTXRATE4, RID_WORD),
	RID(CURRENTTXRATE5, RID_WORD),
	RID(CURRENTTXRATE6, RID_WORD),
	RID(OWNMACADDR, RID_HWADDR),
	RID(SCANRESULTSTABLE, RID_HEXDUMP),
	RID(HOSTSCANRESULTS, RID_HEXDUMP),
	RID(AUTHENTICATIONUSED, RID_HEXDUMP),
	RID(CNFFAASWITCHCTRL, RID_WORD),
	RID(ASSOCIATIONFAILURE, RID_HEXDUMP),
	RID(PHYTYPE, RID_WORD),
	RID(CURRENTCHANNEL, RID_WORD),
	RID(CURRENTPOWERSTATE, RID_WORD),
	RID(CCAMODE, RID_WORD),
	RID(SUPPORTEDDATARATES, RID_HEXSTRING),
	RID(LFO_VOLT_REG_TEST_RES, RID_HEXDUMP),

	RID(BUILDSEQ, RID_HEXDUMP),
	RID(FWID, RID_STRING)
};


static void diag_show_known_rids(const char *dev)
{
	char buf[PRISM2_HOSTAPD_MAX_BUF_SIZE];
	u8 *rid;
	struct prism2_hostapd_param *param;
	int res, i, j, k, len, slen;
	struct hfa384x_comp_ident *compid;
	struct hfa384x_sup_range *range;

	printf("\nKnown RIDs (Resource IDentifiers)\n\n");

	param = (struct prism2_hostapd_param *) buf;

	for (i = 0; i < sizeof(rid_table) / sizeof(rid_table[0]); i++) {
		res = hostapd_get_rid(dev, param, rid_table[i].rid, 0);
		if (res == ENODATA)
			continue;
		if (res) {
			printf("Could not read RID %04X (res=%d)\n",
			       rid_table[i].rid, res);
			break;
		}

		printf("%04X=%s=", rid_table[i].rid, rid_table[i].name);
		rid = param->u.rid.data;
		len = param->u.rid.len;

		switch (rid_table[i].type) {
		case RID_HEXDUMP:
			for (j = 0; j < len; j++)
				printf("<%02x>", rid[j]);
			printf("\n");
			break;

		case RID_WORD:
			if (len != 2) {
				printf("<INVALID RID_WORD LEN %d>\n", len);
			} else {
				u16 val = le_to_host16(*(u16 *)rid);
				printf("%d\n", val);
			}
			break;

		case RID_HWADDR:
			if (len != 6) {
				printf("<INVALID RID_HWADDR LEN %d>\n", len);
			} else {
				printf(MACSTR "\n", MAC2STR(rid));
			}
			break;

		case RID_STRING:
			slen = le_to_host16(*(u16 *)rid);
			if (slen > len)
				slen = len;
			for (j = 2; j < slen + 2; j++) {
				if (rid[j] >= 32 && rid[j] < 127)
					printf("%c", rid[j]);
				else
					printf("<%02x>", rid[j]);
			}
			printf("\n");
			break;

		case RID_COMPID:
			if (len != sizeof(*compid)) {
				printf("<INVALID RID_COMPID LEN "
					     "%d>\n", len);
				break;
			}
			compid = (struct hfa384x_comp_ident *) rid;
			printf("0x%02x v%d.%d.%d\n",
				     le_to_host16(compid->id),
				     le_to_host16(compid->major),
				     le_to_host16(compid->minor),
				     le_to_host16(compid->variant));
			break;

		case RID_SUPRANGE:
			if (len != sizeof(*range)) {
				printf("<INVALID RID_SUPRANGE LEN "
					     "%d>\n", len);
				break;
			}
			range = (struct hfa384x_sup_range *) rid;
			printf("%d 0x%02x %d %d-%d\n",
				     le_to_host16(range->role),
				     le_to_host16(range->id),
				     le_to_host16(range->variant),
				     le_to_host16(range->bottom),
				     le_to_host16(range->top));
			break;

		case RID_HEXSTRING:
			slen = le_to_host16(*(u16 *)rid);
			if (slen > len)
				slen = len;
			for (j = 2; j < slen + 2; j++)
				printf("<%02x>", rid[j]);
			printf("\n");
			break;

		case RID_CIS:
			k = len;
			while (k > 0 && rid[k - 1] == 0xff)
				k--;
			for (j = 0; j < k; j++)
				printf("<%02x>", rid[j]);
			if (k != len)
				printf(" + %d*<ff>", len - k);
			printf("\n");
			break;

		default:
			printf("<UNKNOWN TYPE %d>\n", rid_table[i].type);
			break;
		}
	}
}


static void diag_show_unknown_rids(const char *dev)
{
	char buf[PRISM2_HOSTAPD_MAX_BUF_SIZE];
	struct prism2_hostapd_param *param;
	int res, j;
	u16 rid;
	int pos, rid_entries;

	printf("\nUnknown RIDs (Resource IDentifiers)\n\n");

	param = (struct prism2_hostapd_param *) buf;

	pos = 0;
	rid_entries = sizeof(rid_table) / sizeof(rid_table[0]);

	for (rid = 0xfc00; rid <= 0xfdff; rid++) {
		if (pos < rid_entries) {
			if (rid_table[pos].rid == rid) {
				pos++;
				continue;
			}
			while (pos < rid_entries && rid_table[pos].rid < rid)
				pos++;
		}
		res = hostapd_get_rid(dev, param, rid, 0);
		if (res == ENODATA)
			continue;
		if (res) {
			printf("Could not read RID %04X (res=%d)\n",
			       rid_table[pos].rid, res);
			break;
		}

		printf("%04X=", rid);
		for (j = 0; j < param->u.rid.len; j++)
			printf("<%02x>", param->u.rid.data[j]);
		printf("\n");
	}
}


static inline void show_bbp_cr(const char *dev, int cr, const char *desc,
			       const char *extra)
{
	int res;
	res = hostap_ioctl_readmif(dev, cr);
	if (res >= 0)
		printf("CR%d (%s): %d%s\n", cr, desc, res, extra);
}


static inline void show_bbp_cr_signed(const char *dev, int cr,
				      const char *desc, const char *extra)
{
	int res;
	res = hostap_ioctl_readmif(dev, cr);
	if (res >= 0)
		printf("CR%d (%s): %d%s\n", cr, desc, (signed char) res,
		       extra);
}


static inline void show_a_values(const char *dev)
{
	printf("    CR50..CR63: 'a' value\n");

	show_bbp_cr(dev, 50, "Test Bus Read", "");
	show_bbp_cr(dev, 51, "Noise floorAntA", "");
	show_bbp_cr(dev, 52, "Noise floorAntB", "");
	show_bbp_cr(dev, 53, "AGC error / I DC Offset", "");
	show_bbp_cr(dev, 54, "Unassigned / Q DC Offset", "");
	show_bbp_cr(dev, 55, "Unassigned  Multipath Metric", "");
	show_bbp_cr(dev, 56, "Unassigned / Multipath Count", "");
	show_bbp_cr(dev, 57, "Unassigned / Packet Signal Quality", "");
	show_bbp_cr_signed(dev, 58, "TX Power Measurement", "");
	show_bbp_cr(dev, 59, "RX Mean Power / Header Signal Quality", "");
}


static inline void show_b_values(const char *dev)
{
	printf("    CR50..CR63: 'b' value\n");

	show_bbp_cr(dev, 50, "Test Bus Read", "");
	show_bbp_cr(dev, 51,
		    "Signal Quality Measure Based on Carrier Tracking", "");
	show_bbp_cr(dev, 52, "Received Signal Field", "");
	show_bbp_cr(dev, 53, "Received Service Field", "");
	show_bbp_cr(dev, 54, "Received Length Field, Low", "");
	show_bbp_cr(dev, 55, "Received Length Field, High", "");
	show_bbp_cr(dev, 56, "Calculated CRC on Received Header, Low", "");
	show_bbp_cr(dev, 57, "Calculated CRC on Received Header, High", "");
	show_bbp_cr_signed(dev, 58, "TX Power Measurement", "");
	show_bbp_cr(dev, 59, "RX Mean Power", "");
}


static void diag_show_bbp(const char *dev)
{
	int res, res2;

	/* This info is based on Intersil FN4816 (HFA3861B Data Sheet) */

	printf("\nBaseband proccessor (BBP) Configuration Registers\n\n");

	res = hostap_ioctl_readmif(dev, 0);
	if (res >= 0) {
		int part, version;
		part = res / 16;
		version = res % 16;
		printf("CR0 (Part/Version Code): %d - Part=%d ", res, part);
		switch (part) {
		case 1: printf("(HFA3861B series)"); break;
		case 3: printf("(HFA3863 series)"); break;
		case 7: printf("(HFA3871 series?)"); break;
		default: printf("(unknown)"); break;
		}
		printf(" Version=%d ", version);
		switch (version) {
		case 0: printf("(3863 Version)"); break;
		case 3: printf("(3861B Version)"); break;
		case 4: printf("(3871 Version?)"); break;
		default: printf("(unknown)"); break;
		}
		printf("\n");
	}

	res = hostap_ioctl_readmif(dev, 1);
	if (res >= 0) {
		printf("CR1 (I/O Polarity): %d (normal setting 0)\n", res);
		printf("    Phase of RX carrier rotation sense: %s\n",
		       res & BIT(7) ?
		       "Inverted rotation (CW), Invert Q in" :
		       "normal rotation (CCW)");
		printf("    Phase of TX carrier rotation sense: %s\n",
		       res & BIT(6) ?
		       "Inverted rotation (CW), Invert Q out" :
		       "normal rotation (CCW)");
		printf("    Phase of TX output clock (TXCLK) pin: %s\n",
		       res & BIT(5) ? "Inverted TXCLK" : "NON-Inverted TXCLK");
		printf("    Active level of the Transmit Ready output: %s\n",
		       res & BIT(4) ? "TX_RDY Active 0" : "TX_RDY Active 1");
		printf("    Active level of the transmit enable input: %s\n",
		       res & BIT(3) ? "TX_PE Active 0" : "TX_PE Active 1");
		printf("    Active level of the Clear Channel Assessment "
		       "output: %s\n",
		       res & BIT(2) ? "CCA Active 1" : "CCA Active 0");
		printf("    Active level of the MD_RDY output: %s\n",
		       res & BIT(1) ? "MD_RDY Active 0" : "MD_RDY Active 1");
		printf("    Phase of the RX_CLK output: %s\n",
		       res & BIT(0) ? "Invert Clk" : "Non-Inverted Clk");
	}

	show_bbp_cr(dev, 2, "I Cover Code", " (nominally 72)");
	show_bbp_cr(dev, 3, "Q Cover Code", " (nominally 72)");
	show_bbp_cr(dev, 4, "TX Preamble Length", " (IEEE 802.11: 128)");

	res = hostap_ioctl_readmif(dev, 5);
	if (res >= 0) {
		printf("CR5 (TX Signal Field): %d\n"
		       "    Preamble mode: %s\n"
		       "    TX data rate: ", res,
		       res & BIT(3) ? "Short preamble and header mode" :
		       "Normal");
		switch (res & (BIT(1) | BIT(0))) {
		case 0:
			printf("00 = DBPSK - 11 chip sequence (1Mbps)\n");
			break;
		case 1:
			printf("01 = DQPSK - 11 chip sequence (2Mbps)\n");
			break;
		case 2:
			printf("10 = CCK - 8 chip sequence (5.5Mbps)\n");
			break;
		case 3:
			printf("11 = CCK - 8 chip sequence (11Mbps)\n");
			break;
		}
	}

	show_bbp_cr(dev, 6, "TX Service Field", "");

	show_bbp_cr(dev, 7, "TX Length Field, High", "");
	show_bbp_cr(dev, 8, "TX Length Field, Low", "");
	res = hostap_ioctl_readmif(dev, 7);
	res2 = hostap_ioctl_readmif(dev, 8);
	if (res >= 0 && res2 >= 0)
		printf("    TX Length Field: %d usec\n",
		       (res << 8) | res2);

	res = hostap_ioctl_readmif(dev, 9);
	if (res >= 0) {
		printf("CR9 (TX Configure): %d\n", res);
		printf("    CCA sample mode time: %s usec\n",
		       res & BIT(7) ? "15.8" : "19.9");
		printf("    CCA mode: CCA is based ");
		switch ((res & (BIT(6) | BIT(5))) >> 5) {
		case 0: printf("only on ED\n"); break;
		case 1: printf("on (CS1 OR SQ1/CS2)\n"); break;
		case 2: printf("on (ED AND (CS1 OR SQ1/CS2))\n"); break;
		case 3: printf("on (ED OR (CS1 OR SQ1/CS2))\n"); break;
		}
		printf("    TX test modes: %s\n",
		       res & BIT(4) ? "all chips set to 1 for CW carrier" :
		       "Alternating bits for carrier suppression test");
		printf("    Enable TX test modes: %s\n",
		       res & BIT(3) ? "Invoke tests described above" :
		       "normal operation");
		printf("    Antenna choice for TX: Set AntSel %s\n",
		       res & BIT(2) ? "high" : "low");
		printf("    TX Antenna Mode: set AntSel pin to %s\n",
		       res & BIT(1) ? "antenna for which last valid header CRC"
		       " occurred" : "value in choice above");
	}

	res = hostap_ioctl_readmif(dev, 10);
	if (res >= 0) {
		printf("CR10 (RX Configure): %d\n", res);
		printf("    Initial CS2 estimate: Use %s\n",
		       res & BIT(7) ? "SQ1 from Barker correlator peaks" :
		       "dot product result");
		printf("    CIR estimate/Dot product clock control: %s\n",
		       res & BIT(6) ? "only on after detect" :
		       "on during acquisition");
		printf("    SFD Time-out values: ");
		switch ((res & (BIT(5) | BIT(4))) > 4) {
		case 0: printf("56 usec\n"); break;
		case 1: printf("64 usec\n"); break;
		case 2: printf("128 usec\n"); break;
		case 3: printf("144 usec\n"); break;
		}
		printf("    MD_RDY control: After %s\n",
		       res & BIT(3) ? "SFD" : "CRC16");
		printf("    Force Frequency Offset Estimating in all antenna "
		       "diversity timelines: %s\n",
		       res & BIT(2) ? "enabled" : "disabled");
		printf("    Antenna choice for RX when single antenna "
		       "acquisition is selected: AntSel pin %s\n",
		       res & BIT(1) ? "high" : "low");
		printf("    Antenna acquire: %s\n",
		       res & BIT(0) ? "single antenna" :
		       "dual antenna for diversity acquisition");
	}

	res = hostap_ioctl_readmif(dev, 11);
	if (res >= 0) {
		printf("CR11 (RX/TX Configure): %d\n", res);
		printf("    Continuous internal RX 22 and 44 MHZ clocks: %d\n",
		       res & BIT(7) ? 1 : 0);
		printf("    A/D input coupling: %s\n",
		       res & BIT(6) ? "AC (external bias network required)" :
		       "DC");
		printf("    TX filter / CMF weight select: %s\n",
		       res & BIT(5) ? "Japan" : "US");
		printf("    Ping Pong Differential Encode: %s\n",
		       res & BIT(4) ? "normal" : "disabled");
		printf("    CCA mode: %s\n",
		       res & BIT(3) ? "Sampled CCA; CCA will update once per "
		       "slot (20 usec)" : "normal CCA; CCA will immediately "
		       "respond to changes in ED, CS1, and SQ1");
		printf("    Precursor value in CIR estimate: %d\n",
		       res & (BIT(2) | BIT(1) | BIT(0)));
	}

	res = hostap_ioctl_readmif(dev, 12);
	if (res >= 0) {
		printf("CR12 (A/D Test Modes 1): %d\n", res);
		printf("    All DAC and A/D clock source control: %s\n",
		       res & BIT(7) ? "clock via SDI pin" :
		       "normal internal clocks");
		printf("    TX DAC clock: %s\n",
		       res & BIT(6) ? "disable" : "enable");
		printf("    RX DAC clock: %s\n",
		       res & BIT(5) ? "disable" : "enable");
		printf("    I DAC clock: %s\n",
		       res & BIT(4) ? "disable" : "enable");
		printf("    Q DAC clock: %s\n",
		       res & BIT(3) ? "disable" : "enable");
		printf("    RF A/D clock: %s\n",
		       res & BIT(2) ? "disable" : "enable");
		printf("    I A/D clock: %s\n",
		       res & BIT(1) ? "disable" : "enable");
		printf("    Q A/D clock: %s\n",
		       res & BIT(0) ? "disable" : "enable");
	}

	res = hostap_ioctl_readmif(dev, 13);
	if (res >= 0) {
		printf("CR13 (A/D Test Modes 2): %d\n", res);
		printf("    Standby: %s\n",
		       res & BIT(7) ? "enable" : "disable");
		printf("    SLEEP TX: %s\n",
		       res & BIT(6) ? "enable" : "disable");
		printf("    SLEEP RX: %s\n",
		       res & BIT(5) ? "enable" : "disable");
		printf("    SLEEP IQ: %s\n",
		       res & BIT(4) ? "enable" : "disable");
		printf("    Analog TX Shut_down: %s\n",
		       res & BIT(3) ? "enable" : "disable");
		printf("    Analog RX Shut_down: %s\n",
		       res & BIT(2) ? "enable" : "disable");
		printf("    Analog Standby: %s\n",
		       res & BIT(1) ? "enable" : "disable");
		printf("    Manual control of mixed signal power down "
		       "signals (other CR13 bits): %s\n",
		       res & BIT(0) ? "enable" : "disable");
	}

	res = hostap_ioctl_readmif(dev, 14);
	if (res >= 0) {
		printf("CR14 (A/D Test Modes 3): %d\n", res);
		printf("    DFS - select straight binary output of I/Q and "
		       "RF A/D converters: %d\n",
		       res & BIT(7) ? 1 : 0);
		printf("    I/Q DAC input control: ");
		switch ((res & (BIT(6) | BIT(5) | BIT(4))) >> 4) {
		case 0: printf("normal (TX filter)\n"); break;
		case 1: printf("down converter\n"); break;
		case 2:
			printf("E/L integrator - upper 6 bits (Q) and AGC "
			       "error (I)\n");
			break;
		case 3: printf("I/Q A/D's\n"); break;
		case 4:
			printf("Bigger picker output - upper 6 bits of FWT_I "
			       "winner and FWT_Q winner\n");
			break;
		case 5:
			printf("CMF weights - upper 6 bits of all 16 CMF "
			       "weights circularly shifted with full scale "
			       "negative sync pulse interleaved between "
			       "them\n");
			break;
		case 6:
			printf("Test Bus pins (5:0) when configured as "
			       "inputs\n");
			break;
		case 7: printf("Barker Correlator/low rate samples\n"); break;
		}
		printf("    Enable test bus into RX and TX DAC: %s\n",
		       res & BIT(3) ? "enable" : "disable");
		printf("    Enable RF A/D into RX DAC: %s\n",
		       res & BIT(2) ? "enable" : "disable");
		printf("    VRbit1: %d\n", res & BIT(1) ? 1 : 0);
		printf("    VRbit0: %d\n", res & BIT(0) ? 1 : 0);
	}

	show_bbp_cr(dev, 15, "AGC GainClip", "");

	res = hostap_ioctl_readmif(dev, 16);
	if (res >= 0) {
		printf("CR16 (AGC Sat Cpints): %d\n", res);
		printf("    AGC mid Sat counts: %d\n",
		       (res & (BIT(7) | BIT(6) | BIT(5) | BIT(4))) >> 4);
		printf("    AGC low Sat counts: %d\n",
		       res & (BIT(3) | BIT(2) | BIT(1) | BIT(0)));
	}

	res = hostap_ioctl_readmif(dev, 17);
	if (res >= 0) {
		printf("CR17 (AGC Update Control): %d\n", res);
		printf("    AGC update during CIR injest: %s\n",
		       res & BIT(7) ? "enable" : "disable");
		printf("    AGC timer count: %d (must be >31)\n",
		       res & (BIT(5) | BIT(4) | BIT(3) | BIT(2) | BIT(1) |
			      BIT(0)));
	}

	show_bbp_cr(dev, 18, "AGC HiSat", "");
	show_bbp_cr(dev, 19, "AGC LockinLevel/CW detect threshold", "");
	show_bbp_cr(dev, 20, "AGC LockWindow, pos side", "");
	show_bbp_cr(dev, 21, "AGC Threshold", "");
	show_bbp_cr(dev, 22, "AGC Lookup Table Addr and Control", "");
	show_bbp_cr(dev, 23, "AGC Lookup Table Data", "");
	show_bbp_cr(dev, 24, "AGC LoopGain", "");
	show_bbp_cr(dev, 25, "AGC RX_IF", "");
	show_bbp_cr(dev, 26, "AGC Test Modes", "");
	show_bbp_cr(dev, 27, "AGC RX_RF Threshold", "");
	show_bbp_cr(dev, 28, "AGC Low SatAtten", "");
	show_bbp_cr(dev, 29, "AGC LockWindow, negative side", "");
	show_bbp_cr(dev, 30, "Carrier Sense 2", "");
	show_bbp_cr(dev, 31, "Manual TX Power Control", "");
	show_bbp_cr(dev, 32, "Test Modes 1", "");
	show_bbp_cr(dev, 33, "Test Modes 2", "");
	show_bbp_cr(dev, 34, "Test Bus Address", "");
	show_bbp_cr(dev, 35, "CMF Coefficient Control", "");
	show_bbp_cr(dev, 36, "Scrambler Seed, Long Preamble Option", "");
	show_bbp_cr(dev, 37, "Scrambler Seed, Short Preamble Option", "");
	show_bbp_cr(dev, 38, "ED Threshold", "");
	show_bbp_cr(dev, 39, "CMF Gain Threshold", "");
	show_bbp_cr(dev, 40, "Threshold for antenna decision", "");
	show_bbp_cr(dev, 41, "Preamble tracking loop lead coefficient", "");
	show_bbp_cr(dev, 42, "Preamble tracking loop lag coefficient", "");
	show_bbp_cr(dev, 43, "Header tracking loop lead coefficient", "");
	show_bbp_cr(dev, 44, "Header tracking loop lag coefficient", "");
	show_bbp_cr(dev, 45, "Data tracking loop lead coefficient", "");
	show_bbp_cr(dev, 46, "Data tracking loop lag coefficient", "");
	show_bbp_cr(dev, 47, "RF attenuator value", "");
	show_bbp_cr(dev, 48, "ED and SQ1 control and SQ1 scale factor", "");

	res = hostap_ioctl_readmif(dev, 49);
	if (res >= 0) {
		printf("CR49 (Read only register mux control for registers 50 "
		    "to 63): %d\n", res);
		printf("    CW RSSI threshold: %d\n", res & 127);
		if (res & 128)
			show_a_values(dev);
		else
			show_b_values(dev);
	}

	show_bbp_cr(dev, 60, "RX_IF AGC", "");

	res = hostap_ioctl_readmif(dev, 61);
	if (res >= 0) {
		printf("CR61 (RX Status Reg): %d\n", res);
		if (res & BIT(4))
			printf("    ED, energy detect past threshold\n");
		if (res & BIT(3))
			printf("    TX PWR det Register semaphore (CR58 "
			       "updated since last read)\n");
		if (res & BIT(2))
			printf("    AGC_lock (AGC is within limits of lock "
			       "window CR20)\n");
		if (res & BIT(1))
			printf("    hwStopBHit (rails hit, AGC updates "
			       "stopped)\n");
		if (res & BIT(0))
			printf("    RX_RF_AGC - status of AGC output to RF "
			       "chip\n");
	}


	show_bbp_cr(dev, 62, "RSSI", "");

	res = hostap_ioctl_readmif(dev, 63);
	if (res >= 0) {
		int val;
		printf("CR63 (RX Status Reg): %d\n", res);
		val = (res & (BIT(7) | BIT(6))) >> 6;
		printf("    Signal field value: ");
		switch (val) {
		case 0: printf("1 M\n"); break;
		case 1: printf("2 M\n"); break;
		case 2: printf("5.5 M\n"); break;
		case 3: printf("11 M\n"); break;
		}
		if (res & BIT(5))
			printf("    SFD found\n");
		if (res & BIT(4))
			printf("    Short preamble detected\n");
		if (res & BIT(3))
			printf("    Valid signal field found\n");
		if (res & BIT(2))
			printf("    Valid CRC 16\n");
		if (res & BIT(1))
			printf("    Antenna selected by received when last "
			       "valid header CRC occurred\n");
		if (res & BIT(0))
			printf("    not used\n");
	}
}


static void diag_show_pda(const char *dev)
{
	char fname[256];
	struct prism2_pda pda;
	int i, j;

	printf("\nProduction Data Area (PDA)\n\n");

	snprintf(fname, sizeof(fname), "/proc/net/hostap/%s/pda", dev);
	if (read_wlan_pda(fname, &pda)) {
		printf("Could not read wlan PDA. This requires "
		       "PRISM2_DOWNLOAD_SUPPORT definition for the kernel "
		       "driver.\n");
		return;
	}

	for (i = 0; i < pda.pdr_count; i++) {
		printf("PDR 0x%04x len=%i %s\n  ",
		       pda.pdrs[i].pdr, pda.pdrs[i].len,
		       prism2_pdr_name(pda.pdrs[i].pdr));
		for (j = 0; j < pda.pdrs[i].len; j++)
			printf(" %02x", pda.pdrs[i].data[j]);
		printf("\n");
	}

	free(pda.pdrs);
}


static void usage(void)
{
	printf("Usage: hostap_diag [-abhpru] <device>\n"
	       "Options:\n"
	       "  -h      show this usage info\n"
	       "  -a      show all info\n"
	       "  -b      show baseband processor control registers\n"
	       "  -p      show production data area (PDA)\n"
	       "  -r      show known RIDs\n"
	       "  -u      show unknown RIDs\n");

	exit(1);
}


int main(int argc, char *argv[])
{
	int c;
	int show_known_rids = 0;
	int show_unknown_rids = 0;
	int show_bbp = 0;
	int show_pda = 0;
	char *dev;

	for (;;) {
		c = getopt(argc, argv, "abhpru");
		if (c < 0)
			break;
		if (c == 'a') {
			show_known_rids = 1;
			show_unknown_rids = 1;
			show_bbp = 1;
			show_pda = 1;
		} else if (c == 'b')
			show_bbp = 1;
		else if (c == 'h')
			usage();
		else if (c == 'r')
			show_known_rids = 1;
		else if (c == 'u')
			show_unknown_rids = 1;
		else if (c == 'p')
			show_pda = 1;
		else
			usage();
	}

	if (argc != optind + 1)
		usage();

	dev = argv[optind];

	if (diag_show_summary(dev))
		exit(1);

	if (show_known_rids)
		diag_show_known_rids(dev);

	if (show_unknown_rids)
		diag_show_unknown_rids(dev);

	if (show_bbp)
		diag_show_bbp(dev);

	if (show_pda)
		diag_show_pda(dev);

	return 0;
}
