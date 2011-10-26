/* $Id$ */

/*
 * ** Copyright (C) 2005 Sourcefire, Inc.
 * ** AUTHOR: Steven Sturges
 * **
 * ** This program is free software; you can redistribute it and/or modify
 * ** it under the terms of the GNU General Public License as published by
 * ** the Free Software Foundation; either version 2 of the License, or
 * ** (at your option) any later version.
 * **
 * ** This program is distributed in the hope that it will be useful,
 * ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 * ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * ** GNU General Public License for more details.
 * **
 * ** You should have received a copy of the GNU General Public License
 * ** along with this program; if not, write to the Free Software
 * ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * */

/* stream_api.h
 *
 * Purpose: Definition of the StreamAPI.  To be used as a common interface
 *          for TCP (and later UDP & ICMP) Stream access for other 
 *          preprocessors and detection plugins.
 *
 * Arguments:
 *
 * Effect:
 *
 * Comments:
 *
 * Any comments?
 *
 */

#ifndef STREAM_API_H_
#define STREAM_API_H_

#include <sys/types.h>

#include "snort_packet_header.h"
#include "preprocids.h" /* IDs are used when setting preproc specific data */
#include "bitop.h"

#define IGNORE_FLAG_ALWAYS 0x01

#define SSN_DIR_NONE 0x0
#define SSN_DIR_CLIENT 0x1
#define SSN_DIR_SENDER 0x1
#define SSN_DIR_SERVER 0x2
#define SSN_DIR_RESPONDER 0x2
#define SSN_DIR_BOTH 0x03

#define SSNFLAG_SEEN_CLIENT         0x00000001
#define SSNFLAG_SEEN_SENDER         0x00000001
#define SSNFLAG_SEEN_SERVER         0x00000002
#define SSNFLAG_SEEN_RESPONDER      0x00000002
#define SSNFLAG_ESTABLISHED         0x00000004
#define SSNFLAG_NMAP                0x00000008
#define SSNFLAG_ECN_CLIENT_QUERY    0x00000010
#define SSNFLAG_ECN_SERVER_REPLY    0x00000020
#define SSNFLAG_HTTP_1_1            0x00000040 /* has stream seen HTTP 1.1? */
#define SSNFLAG_SEEN_PMATCH         0x00000080 /* seen pattern match? */
#define SSNFLAG_MIDSTREAM           0x00000100 /* picked up midstream */
#define SSNFLAG_CLIENT_FIN          0x00000200 /* server sent fin */
#define SSNFLAG_SERVER_FIN          0x00000400 /* client sent fin */
#define SSNFLAG_CLIENT_PKT          0x00000800 /* packet is from the client */
#define SSNFLAG_SERVER_PKT          0x00001000 /* packet is from the server */
#define SSNFLAG_ALL                 0xFFFFFFFF /* all that and a bag of chips */

#define STREAM_FLPOLICY_NONE            0x00
#define STREAM_FLPOLICY_FOOTPRINT       0x01 /* size-based footprint flush */
#define STREAM_FLPOLICY_LOGICAL         0x02 /* queued bytes-based flush */
#define STREAM_FLPOLICY_RESPONSE        0x03 /* flush when we see response */
#define STREAM_FLPOLICY_SLIDING_WINDOW  0x04 /* flush on sliding window */
#define STREAM_FLPOLICY_CONSUMED        0x05 /* purge consumed bytes */
#define STREAM_FLPOLICY_IGNORE          0x06 /* ignore this traffic */

#define STREAM_FLPOLICY_MAX STREAM_FLPOLICY_IGNORE

#define STREAM_FLPOLICY_SET_ABSOLUTE    0x01
#define STREAM_FLPOLICY_SET_APPEND      0x02

#define UNKNOWN_PORT 0

#define STREAM_API_VERSION4 4
#define STREAM_API_VERSION5 5

typedef void (*StreamAppDataFree)(void *);
typedef int (*PacketIterator)(SnortPktHeader *,
                              u_int8_t *,
                              void *); /* user-defined data pointer */

typedef struct _StreamFlowData
{
    BITOP boFlowbits;
    unsigned char flowb[1];
} StreamFlowData;

typedef struct _stream_api
{
    int version;

    /*
     * Drop on Inline Alerts for Midstream pickups
     *
     * Parameters
     *
     * Returns
     *     0 if not alerting
     *     !0 if alerting
     */
    int (*alert_inline_midstream_drops)();

    /* Set direction of session
     *
     * Parameters:
     *     Session Ptr
     *     New Direction
     *     IP
     *     Port
     */
    void (*update_direction)(void *, char, u_int32_t, u_int16_t );

    /* Stop inspection for session, up to count bytes (-1 to ignore
     * for life or until resume).
     *
     * If response flag is set, automatically resume inspection up to
     * count bytes when a data packet in the other direction is seen.
     *
     * Also marks the packet to be ignored
     *
     * Parameters
     *     Session Ptr
     *     Packet
     *     Direction
     *     Bytes
     *     Response Flag
     */
    void (*stop_inspection)(void *, Packet *, char, int32_t, int);

    /* Turn off inspection for potential session.
     * Adds session identifiers to a hash table.
     * TCP only.
     *
     * Parameters
     *     IP addr #1
     *     Port #1
     *     IP addr #2
     *     Port #2
     *     Protocol
     *     Direction
     *     Flags (permanent)
     *
     * Returns
     *     0 on success
     *     -1 on failure
     */
    int (*ignore_session)(u_int32_t, u_int16_t, u_int32_t, u_int16_t,
                          char, char, char);

    /* Resume inspection for session.
     *
     * Parameters
     *     Session Ptr
     *     Direction
     */
    void (*resume_inspection)(void *, char);

    /* Drop traffic arriving on session.
     *
     * Parameters
     *     Session Ptr
     *     Direction
     */
    void (*drop_traffic)(void *, char);

    /* Drop retransmitted packet arriving on session.
     *
     * Parameters
     *     Packet
     */
    void (*drop_packet)(Packet *);

    /* Set a reference to application data for a session
     *
     * Parameters
     *     Session Ptr
     *     Application Protocol
     *     Application Data reference (pointer)
     *     Application Data free function
     */
    void (*set_application_data)(void *, u_int32_t, void *, StreamAppDataFree);

    /* Set a reference to application data for a session
     *
     * Parameters
     *     Session Ptr
     *     Application Protocol
     *
     * Returns
     *     Application Data reference (pointer)
     */
    void *(*get_application_data)(void *, u_int32_t);

    /* Sets the flags for a session
     * This ORs the supplied flags with the previous values
     * 
     * Parameters
     *     Session Ptr
     *     Flags
     *
     * Returns
     *     New Flags
     */
    u_int32_t (*set_session_flags)(void *, u_int32_t);

    /* Gets the flags for a session
     *
     * Parameters
     *     Session Ptr
     */
    u_int32_t (*get_session_flags)(void *);

    /* Flushes the stream on an alert
     * Side that is flushed is the same as the packet.
     *
     * Parameters
     *     Packet
     */
    int (*alert_flush_stream)(Packet *);

    /* Flushes the stream on arrival of another packet
     * Side that is flushed is the opposite of the packet.
     *
     * Parameters
     *     Packet
     */
    int (*response_flush_stream)(Packet *);

    /* Calls user-provided callback function for each packet of
     * a reassembled stream.  If the callback function returns non-zero,
     * iteration ends.
     *
     * Parameters
     *     Packet
     *     Packet Iterator Function (called for each packet in the stream)
     *     user data (may be NULL)
     *
     * Returns
     *     number of packets
     */
    int (*traverse_reassembled)(Packet *, PacketIterator, void *userdata);

    /* Add session alert
     *
     * Parameters
     *     Session Ptr
     *     gen ID
     *     sig ID
     *
     * Returns
     *     0 success
     *     -1 failure (max alerts reached)
     *
     */
    int (*add_session_alert)(void *, Packet *p, u_int32_t, u_int32_t);

    /* Check session alert
     *
     * Parameters
     *     Session Ptr
     *     Packet
     *     gen ID
     *     sig ID
     *
     * Returns
     *     0 if not previously alerted
     *     !0 if previously alerted
     */
    int (*check_session_alerted)(void *, Packet *p, u_int32_t, u_int32_t);

    /* Get Flowbits data
     *
     * Parameters
     *     Packet
     *
     * Returns
     *     Ptr to Flowbits Data
     */
    StreamFlowData *(*get_flow_data)(Packet *p);

    /* Set reassembly flush policy/direction for given session
     *
     * Parameters
     *     Session Ptr
     *     Flush Policy
     *     Direction(s)
     *     Flags
     *
     * Returns
     *     direction(s) of reassembly for session
     */
    char (*set_reassembly)(void *, u_int8_t, char, char);

    /* Get reassembly direction for given session
     *
     * Parameters
     *     Session Ptr
     *
     * Returns
     *     direction(s) of reassembly for session
     */
    char (*get_reassembly_direction)(void *);

    /* Get reassembly flush_policy for given session
     *
     * Parameters
     *     Session Ptr
     *     Direction
     *
     * Returns
     *     flush policy for specified direction
     */
    char (*get_reassembly_flush_policy)(void *, char);

    /* Get true/false as to whether stream data is in
     * sequence or packets are missing
     *
     * Parameters
     *     Direction
     *     Session Ptr
     *
     * Returns
     *     true/false
     */
    char (*is_stream_sequenced)(void *, char);

} StreamAPI;

/* To be set by Stream5 (or Stream4) */
extern StreamAPI *stream_api;

#endif /* STREAM_API_H_ */

