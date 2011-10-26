#ifndef _IPFIX_PROTOCOL_H
#define _IPFIX_PROTOCOL_H

/* This header file defines structures for the IPFIX protocol in accordance with
 * draft-ietf-ipfix-protocol-19.txt */

#define IPFIX_VENDOR_IETF	0x00000000
#define IPFIX_VENDOR_NETFILTER	0x23424223

/* Section 3.1 */
struct ipfix_msg_hdr {
	u_int16_t	version;
	u_int16_t	length;
	u_int32_t	export_time;
	u_int32_t	seq;
	u_int32_t	source_id;
};

/* Section 3.4.1 */
struct ipfix_templ_rec_hdr {
	u_int16_t	templ_id;
	u_int16_t	field_count;
};

/* Section 3.2 */
struct ipfix_ietf_field {
	u_int16_t	type;
	u_int16_t	length;
};

struct ipfix_vendor_field {
	u_int16_t	type;
	u_int16_t	length;
	u_int32_t	enterprise_num;
};

/* Information Element Identifiers as of draft-ietf-ipfix-info-11.txt */
enum {
	IPFIX_octetDeltaCount		= 1,
	IPFIX_packetDeltaCount		= 2,
	/* reserved */
	IPFIX_protocolIdentifier	= 4,
	IPFIX_classOfServiceIPv4	= 5,
	IPFIX_tcpControlBits		= 6,
	IPFIX_sourceTransportPort	= 7,
	IPFIX_sourceIPv4Address		= 8,
	IPFIX_sourceIPv4Mask		= 9,
	IPFIX_ingressInterface		= 10,
	IPFIX_destinationTransportPort	= 11,
	IPFIX_destinationIPv4Address	= 12,
	IPFIX_destinationIPv4Mask	= 13,
	IPFIX_egressInterface		= 14,
	IPFIX_ipNextHopIPv4Address	= 15,
	IPFIX_bgpSourceAsNumber		= 16,
	IPFIX_bgpDestinationAsNumber	= 17,
	IPFIX_bgpNextHopIPv4Address	= 18,
	IPFIX_postMCastPacketDeltaCount	= 19,
	IPFIX_postMCastOctetDeltaCount	= 20,
	IPFIX_flowEndSysUpTime		= 21,
	IPFIX_flowStartSysUpTime	= 22,
	IPFIX_postOctetDeltaCount	= 23,
	IPFIX_postPacketDeltaCount	= 24,
	IPFIX_minimumPacketLength	= 25,
	IPFIX_maximumPacketLength	= 26,
	IPFIX_sooureIPv6Address		= 27,
	IPFIX_destinationIPv6Address	= 28,
	IPFIX_sourceIPv6Mask		= 29,
	IPFIX_destinationIPv6Mask	= 30,
	IPFIX_flowLabelIPv6		= 31,
	IPFIX_icmpTypeCodeIPv4		= 32,
	IPFIX_igmpType			= 33,
	/* reserved */
	/* reserved */
	IPFIX_flowActiveTimeOut		= 36,
	IPFIX_flowInactiveTimeout	= 37,
	/* reserved */
	/* reserved */
	IPFIX_exportedOctetTotalCount	= 40,
	IPFIX_exportedMessageTotalCount	= 41,
	IPFIX_exportedFlowTotalCount	= 42,
	/* reserved */
	IPFIX_sourceIPv4Prefix		= 44,
	IPFIX_destinationIPv4Prefix	= 45,
	IPFIX_mplsTopLabelType		= 46,
	IPFIX_mplsTopLabelIPv4Address	= 47,
	/* reserved */
	/* reserved */
	/* reserved */
	/* reserved */
	IPFIX_minimumTtl		= 52,
	IPFIX_maximumTtl		= 53,
	IPFIX_identificationIPv4	= 54,
	IPFIX_postClassOfServiceIPv4	= 55,
	IPFIX_sourceMacAddress		= 56,
	IPFIX_postDestinationMacAddr	= 57,
	IPFIX_vlanId			= 58,
	IPFIX_postVlanId		= 59,
	IPFIX_ipVersion			= 60,
	/* reserved */
	IPFIX_ipNextHopIPv6Address	= 62,
	IPFIX_bgpNexthopIPv6Address	= 63,
	IPFIX_ipv6ExtensionHeaders	= 64,
	/* reserved */
	/* reserved */
	/* reserved */
	/* reserved */
	/* reserved */
	IPFIX_mplsTopLabelStackEntry	= 70,
	IPFIX_mplsLabelStackEntry2	= 71,
	IPFIX_mplsLabelStackEntry3	= 72,
	IPFIX_mplsLabelStackEntry4	= 73,
	IPFIX_mplsLabelStackEntry5	= 74,
	IPFIX_mplsLabelStackEntry6	= 75,
	IPFIX_mplsLabelStackEntry7	= 76,
	IPFIX_mplsLabelStackEntry8	= 77,
	IPFIX_mplsLabelStackEntry9	= 78,
	IPFIX_mplsLabelStackEntry10	= 79,
	IPFIX_destinationMacAddress	= 80,
	IPFIX_postSourceMacAddress	= 81,
	/* reserved */
	/* reserved */
	/* reserved */
	IPFIX_octetTotalCount		= 85,
	IPFIX_packetTotalCount		= 86,
	/* reserved */
	IPFIX_fragmentOffsetIPv4	= 88,
	/* reserved */
	IPFIX_bgpNextAdjacentAsNumber	= 128,
	IPFIX_bgpPrevAdjacentAsNumber	= 129,
	IPFIX_exporterIPv4Address	= 130,
	IPFIX_exporterIPv6Address	= 131,
	IPFIX_droppedOctetDeltaCount	= 132,
	IPFIX_droppedPacketDeltaCount	= 133,
	IPFIX_droppedOctetTotalCount	= 134,
	IPFIX_droppedPacketTotalCount	= 135,
	IPFIX_flowEndReason		= 136,
	IPFIX_classOfServiceIPv6	= 137,
	IPFIX_postClassOFServiceIPv6	= 138,
	IPFIX_icmpTypeCodeIPv6		= 139,
	IPFIX_mplsTopLabelIPv6Address	= 140,
	IPFIX_lineCardId		= 141,
	IPFIX_portId			= 142,
	IPFIX_meteringProcessId		= 143,
	IPFIX_exportingProcessId	= 144,
	IPFIX_templateId		= 145,
	IPFIX_wlanChannelId		= 146,
	IPFIX_wlanSsid			= 147,
	IPFIX_flowId			= 148,
	IPFIX_sourceId			= 149,
	IPFIX_flowStartSeconds		= 150,
	IPFIX_flowEndSeconds		= 151,
	IPFIX_flowStartMilliSeconds	= 152,
	IPFIX_flowEndMilliSeconds	= 153,
	IPFIX_flowStartMicroSeconds	= 154,
	IPFIX_flowEndMicroSeconds 	= 155,
	IPFIX_flowStartNanoSeconds	= 156,
	IPFIX_flowEndNanoSeconds	= 157,
	IPFIX_flowStartDeltaMicroSeconds = 158,
	IPFIX_flowEndDeltaMicroSeconds	= 159,
	IPFIX_systemInitTimeMilliSeconds= 160,
	IPFIX_flowDurationMilliSeconds	= 161,
	IPFIX_flowDurationMicroSeconds 	= 162,
	IPFIX_observedFlowTotalCount	= 163,
	IPFIX_ignoredPacketTotalCount	= 164,
	IPFIX_ignoredOctetTotalCount	= 165,
	IPFIX_notSentFlowTotalCount	= 166,
	IPFIX_notSentPacketTotalCount	= 167,
	IPFIX_notSentOctetTotalCount	= 168,
	IPFIX_destinationIPv6Prefix	= 169,
	IPFIX_sourceIPv6Prefix		= 170,
	IPFIX_postOctetTotalCount	= 171,
	IPFIX_postPacketTotalCount	= 172,
	IPFIX_flowKeyIndicator		= 173,
	IPFIX_postMCastPacketTotalCount	= 174,
	IPFIX_postMCastOctetTotalCount	= 175,
	IPFIX_icmpTypeIPv4		= 176,
	IPFIX_icmpCodeIPv4		= 177,
	IPFIX_icmpTypeIPv6		= 178,
	IPFIX_icmpCodeIPv6		= 179,
	IPFIX_udpSourcePort		= 180,
	IPFIX_udpDestinationPort	= 181,
	IPFIX_tcpSourcePort		= 182,
	IPFIX_tcpDestinationPort	= 183,
	IPFIX_tcpSequenceNumber		= 184,
	IPFIX_tcpAcknowledgementNumber	= 185,
	IPFIX_tcpWindowSize		= 186,
	IPFIX_tcpUrgentPointer		= 187,
	IPFIX_tcpHeaderLength		= 188,
	IPFIX_ipHeaderLength		= 189,
	IPFIX_totalLengthIPv4		= 190,
	IPFIX_payloadLengthIPv6		= 191,
	IPFIX_ipTimeToLive		= 192,
	IPFIX_nextHeaderIPv6		= 193,
	IPFIX_ipClassOfService		= 194,
	IPFIX_ipDiffServCodePoint	= 195,
	IPFIX_ipPrecedence		= 196,
	IPFIX_fragmentFlagsIPv4		= 197,
	IPFIX_octetDeltaSumOfSquares	= 198,
	IPFIX_octetTotalSumOfSquares	= 199,
	IPFIX_mplsTopLabelTtl		= 200,
	IPFIX_mplsLabelStackLength	= 201,
	IPFIX_mplsLabelStackDepth	= 202,
	IPFIX_mplsTopLabelExp		= 203,
	IPFIX_ipPayloadLength		= 204,
	IPFIX_udpMessageLength		= 205,
	IPFIX_isMulticast		= 206,
	IPFIX_internetHeaderLengthIPv4	= 207,
	IPFIX_ipv4Options		= 208,
	IPFIX_tcpOptions		= 209,
	IPFIX_paddingOctets		= 210,
	/* reserved */
	/* reserved */
	IPFIX_headerLengthIPv4		= 213,
	IPFIX_mplsPayloadLength		= 214,
};

/* Information elements of the netfilter vendor id */
enum {
	IPFIX_NF_rawpacket		= 1,	/* pointer */
	IPFIX_NF_rawpacket_length	= 2,	/* u_int32_t */
	IPFIX_NF_prefix			= 3,	/* string */
	IPFIX_NF_mark			= 4,	/* u_int32_t */
	IPFIX_NF_hook			= 5,	/* u_int8_t */
};

#endif
