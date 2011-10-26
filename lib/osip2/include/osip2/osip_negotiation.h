/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001,2002,2003,2004  Aymeric MOIZARD jack@atosc.org
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#ifndef _SDP_NEGOC_H_
#define _SDP_NEGOC_H_

#include <osipparser2/sdp_message.h>


/**
 * @internal
 * @file osip_negotiation.h
 * @brief oSIP and SDP offer/answer model Routines
 *
 */

/**
 * @internal
 * @defgroup oSIP_OAM oSIP and SDP offer/answer model Handling
 * @{
 */

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Structure for applying the SDP offer/answer negotiation.
 * The goal is simply to give:
 *      1.  A configuration (osip_negotiation_t)
 *      2.  A remote SDP packet (generally from the INVITE)
 * The result is the creation of a local answer to
 * the remote SDP packet.
 * @var osip_negotiation_ctx_t
 */
  typedef struct osip_negotiation_ctx osip_negotiation_ctx_t;

/**
 * Structure for applying the SDP offer/answer negotiation.
 * @struct osip_negotiation_ctx
 */
  struct osip_negotiation_ctx
  {
    void *mycontext;		/**< User Defined Pointer */
    sdp_message_t *remote;      /**< Remote SDP offer     */
    sdp_message_t *local;       /**< generated SDP answer */
  };

/**
 * Allocate a negotiation context.
 * @param ctx The element to work on.
 */
  int osip_negotiation_ctx_init (osip_negotiation_ctx_t ** ctx);
/**
 * Free a negotiation context.
 * @param ctx The element to work on.
 */
  void osip_negotiation_ctx_free (osip_negotiation_ctx_t * ctx);

/**
 * Set the context associated to this negotiation.
 * @param ctx The element to work on.
 * @param value A pointer to your personal context.
 */
  int osip_negotiation_ctx_set_mycontext (osip_negotiation_ctx_t * ctx,
					  void *value);
/**
 * Get the context associated to this negotiation.
 * @param ctx The element to work on.
 */
  void *osip_negotiation_ctx_get_mycontext (osip_negotiation_ctx_t * ctx);

/**
 * Set the local SDP packet associated to this negotiation.
 * NOTE: This is done by the 'negotiator'. (You only need to give
 * the remote SDP packet)
 * @param ctx The element to work on.
 * @param sdp The local SDP packet.
 */
  int osip_negotiation_ctx_set_local_sdp (osip_negotiation_ctx_t * ctx,
					  sdp_message_t * sdp);
/**
 * Get the local SDP packet associated to this negotiation.
 * @param ctx The element to work on.
 */
  sdp_message_t *osip_negotiation_ctx_get_local_sdp (osip_negotiation_ctx_t *
						     ctx);
/**
 * Set the remote SDP packet associated to this negotiation.
 * @param ctx The element to work on.
 * @param sdp The remote SDP packet.
 */
  int osip_negotiation_ctx_set_remote_sdp (osip_negotiation_ctx_t * ctx,
					   sdp_message_t * sdp);
/**
 * Get the remote SDP packet associated to this negotiation.
 * @param ctx The element to work on.
 */
  sdp_message_t *osip_negotiation_ctx_get_remote_sdp (osip_negotiation_ctx_t *
						      ctx);


/**
 * Structure for storing the global configuration management.
 * The information you store here is used when computing a
 * remote SDP packet to build a compliant answer.
 * The main objectives is to:
 *    * automaticly refuse unknown media.
 *    * accept some of the known media.
 *    * make sure the SDP answer match the SDP offer.
 *    * simplify the SDP offer/answer model, as all unknown media
 *      are refused without any indication to the application layer.
 *    * In any case, you can still modify the entire SDP packet after
 *      a negotiation if you are not satisfied by the negotiation result.
 * @var osip_negotiation_t
 */
  typedef struct osip_negotiation osip_negotiation_t;

/**
 * Structure for storing the global configuration management.
 * @struct osip_negotiation
 */
  struct osip_negotiation
  {

    char *o_username;               /**< username */
    char *o_session_id;             /**< session identifier */
    char *o_session_version;        /**< session version */
    char *o_nettype;                /**< Network Type */
    char *o_addrtype;               /**< Address type */
    char *o_addr;                   /**< Address */

    char *c_nettype;                /**< Network Type */
    char *c_addrtype;               /**< Address Type */
    char *c_addr;                   /**< Address */
    char *c_addr_multicast_ttl;     /**< TTL value for multicast address  */
    char *c_addr_multicast_int;     /**< Nb of address for multicast */

    osip_list_t *audio_codec;       /**< supported audio codec */
    osip_list_t *video_codec;       /**< supported video codec */
    osip_list_t *other_codec;       /**< supported application */

    int (*fcn_set_info) (void *, sdp_message_t *);   /**< callback for info */
    int (*fcn_set_uri) (void *, sdp_message_t *);    /**< callback for uri */

    int (*fcn_set_emails) (void *, sdp_message_t *); /**< callback for email */
    int (*fcn_set_phones) (void *, sdp_message_t *); /**< callback for phones */
    int (*fcn_set_attributes) (void *, sdp_message_t *, int); /**< callback for attr */
    int (*fcn_accept_audio_codec) (void *, char *, char *, int, char *); /**< callback to accept audio codec during negotiation */
    int (*fcn_accept_video_codec) (void *, char *, char *, int, char *); /**< callback to accept video codec during negotiation */
    int (*fcn_accept_other_codec) (void *, char *, char *, char *, char *); /**< callback to accept application during negotiation */
    char *(*fcn_get_audio_port) (void *, int);   /**< get port for audio stream */
    char *(*fcn_get_video_port) (void *, int);   /**< get port for video stream */
    char *(*fcn_get_other_port) (void *, int);   /**< get port for app stream */

  };


/**
 * Initialise (and Allocate) a sdp_config element (this element is global).
 * Stores the initialized structure to conf_out.
 */
  int osip_negotiation_init (osip_negotiation_t ** conf_out);
/**
 * Free resource stored by a sdp_config element.
 * This method must be called once when the application is stopped.
 */
  void osip_negotiation_free (osip_negotiation_t * conf);

/**
 * Set the local username ('o' field) of all local SDP packet.
 * @param tmp The username.
 */
  int osip_negotiation_set_o_username (osip_negotiation_t *, char *tmp);
/**
 * Set the local session id ('o' field) of all local SDP packet.
 * WARNING: this field should be updated for each new SDP packet?
 * @param tmp The session id.
 */
  int osip_negotiation_set_o_session_id (osip_negotiation_t *, char *tmp);
/**
 * Set the local session version ('o' field) of all local SDP packet.
 * WARNING: this field should be updated for each new SDP packet?
 * @param tmp The session version.
 */
  int osip_negotiation_set_o_session_version (osip_negotiation_t *,
					      char *tmp);
/**
 * Set the local network type ('o' field) of all local SDP packet.
 * @param tmp The network type.
 */
  int osip_negotiation_set_o_nettype (osip_negotiation_t *, char *tmp);
/**
 * Set the local address type ('o' field) of all local SDP packet.
 * @param tmp The address type.
 */
  int osip_negotiation_set_o_addrtype (osip_negotiation_t *, char *tmp);
/**
 * Set the local IP address ('o' field) of all local SDP packet.
 * @param tmp The IP address.
 */
  int osip_negotiation_set_o_addr (osip_negotiation_t *, char *tmp);

/**
 * Set the local network type ('c' field) of all local SDP packet.
 * @param tmp The network type.
 */
  int osip_negotiation_set_c_nettype (osip_negotiation_t *, char *tmp);
/**
 * Set the local address type ('c' field) of all local SDP packet.
 * @param tmp The address type.
 */
  int osip_negotiation_set_c_addrtype (osip_negotiation_t *, char *tmp);
/**
 * Set the local IP address ('c' field) of all local SDP packet.
 * @param tmp The IP address.
 */
  int osip_negotiation_set_c_addr (osip_negotiation_t *, char *tmp);
/**
 * Set the local ttl for multicast address ('c' field) of all local SDP packet.
 * @param tmp The ttl for multicast address.
 */
  int osip_negotiation_set_c_addr_multicast_ttl (osip_negotiation_t *,
						 char *tmp);
/**
 * Set the local int for multicast address ('c' field) of all local SDP packet.
 * @param tmp The int for multicast address.
 */
  int osip_negotiation_set_c_addr_multicast_int (osip_negotiation_t *,
						 char *tmp);

/**
 * Add a supported audio codec.
 * Those codecs will be accepted as long as you return 0 when
 * the callback 'fcn_accept_audio_codec' is called with the specific payload.
 * @param payload The payload.
 * @param number_of_port The number of port (channel) for this codec.
 * @param proto The protocol.
 * @param c_nettype The network type in the 'c' field.
 * @param c_addrtype The address type in the 'c' field.
 * @param c_addr The address in the 'c' field.
 * @param c_addr_multicast_ttl The ttl for multicast address in the 'c' field.
 * @param c_addr_multicast_int The int for multicast address in the 'c' field.
 * @param a_rtpmap The rtpmap attribute in the 'a' field.
 */
  int osip_negotiation_add_support_for_audio_codec (osip_negotiation_t *,
						    char *payload,
						    char *number_of_port,
						    char *proto,
						    char *c_nettype,
						    char *c_addrtype,
						    char *c_addr,
						    char
						    *c_addr_multicast_ttl,
						    char
						    *c_addr_multicast_int,
						    char *a_rtpmap);
/**
 * Add a supported video codec.
 * Those codecs will be accepted as long as you return 0 when
 * the callback 'fcn_accept_video_codec' is called with the specific payload.
 * @param payload The payload.
 * @param number_of_port The number of port (channel) for this codec.
 * @param proto The protocol.
 * @param c_nettype The network type in the 'c' field.
 * @param c_addrtype The address type in the 'c' field.
 * @param c_addr The address in the 'c' field.
 * @param c_addr_multicast_ttl The ttl for multicast address in the 'c' field.
 * @param c_addr_multicast_int The int for multicast address in the 'c' field.
 * @param a_rtpmap The rtpmap attribute in the 'a' field.
 */
  int osip_negotiation_add_support_for_video_codec (osip_negotiation_t *,
						    char *payload,
						    char *number_of_port,
						    char *proto,
						    char *c_nettype,
						    char *c_addrtype,
						    char *c_addr,
						    char
						    *c_addr_multicast_ttl,
						    char
						    *c_addr_multicast_int,
						    char *a_rtpmap);
/**
 * Add a supported (non-audio and non-video) codec.
 * Those codecs will be accepted as long as you return 0 when
 * the callback 'fcn_accept_other_codec' is called with the specific payload.
 * @param payload The payload.
 * @param number_of_port The number of port (channel) for this codec.
 * @param proto The protocol.
 * @param c_nettype The network type in the 'c' field.
 * @param c_addrtype The address type in the 'c' field.
 * @param c_addr The address in the 'c' field.
 * @param c_addr_multicast_ttl The ttl for multicast address in the 'c' field.
 * @param c_addr_multicast_int The int for multicast address in the 'c' field.
 * @param a_rtpmap The rtpmap attribute in the 'a' field.
 */
  int osip_negotiation_add_support_for_other_codec (osip_negotiation_t *,
						    char *payload,
						    char *number_of_port,
						    char *proto,
						    char *c_nettype,
						    char *c_addrtype,
						    char *c_addr,
						    char
						    *c_addr_multicast_ttl,
						    char
						    *c_addr_multicast_int,
						    char *a_rtpmap);

#ifndef DOXYGEN
/**
 * Free resource in the global sdp_config..
 */
  int osip_negotiation_remove_audio_payloads (osip_negotiation_t * config);
/**
 * Free resource in the global sdp_config..
 */
  int osip_negotiation_remove_video_payloads (osip_negotiation_t * config);
/**
 * Free resource in the global sdp_config..
 */
  int osip_negotiation_remove_other_payloads (osip_negotiation_t * config);
#endif

/**
 * Set the callback for setting info ('i' field) in a local SDP packet.
 * This callback is called once each time we need an 'i' field.
 * @param fcn The callback.
 */
  int osip_negotiation_set_fcn_set_info (osip_negotiation_t *,
					 int (*fcn) (osip_negotiation_ctx_t *,
						     sdp_message_t *));
/**
 * Set the callback for setting a URI ('u' field) in a local SDP packet.
 * This callback is called once each time we need an 'u' field.
 * @param fcn The callback.
 */
  int osip_negotiation_set_fcn_set_uri (osip_negotiation_t *,
					int (*fcn) (osip_negotiation_ctx_t *,
						    sdp_message_t *));
/**
 * Set the callback for setting an email ('e' field) in a local SDP packet.
 * This callback is called once each time we need an 'e' field.
 * @param fcn The callback.
 */
  int osip_negotiation_set_fcn_set_emails (osip_negotiation_t *,
					   int (*fcn) (osip_negotiation_ctx_t
						       *, sdp_message_t *));
/**
 * Set the callback for setting a phone ('p' field) in a local SDP packet.
 * This callback is called once each time we need an 'p' field.
 * @param fcn The callback.
 */
  int osip_negotiation_set_fcn_set_phones (osip_negotiation_t *,
					   int (*fcn) (osip_negotiation_ctx_t
						       *, sdp_message_t *));
/**
 * Set the callback for setting an attribute ('a' field) in a local SDP packet.
 * This callback is called once each time we need an 'a' field.
 * @param fcn The callback.
 */
  int
    osip_negotiation_set_fcn_set_attributes (osip_negotiation_t *,
					     int (*fcn)
					     (osip_negotiation_ctx_t *,
					      sdp_message_t *, int));
/**
 * Set the callback used to accept a codec during a negotiation.
 * This callback is called once each time we need to accept a codec.
 * @param fcn The callback.
 */
  int
    osip_negotiation_set_fcn_accept_audio_codec (osip_negotiation_t *,
						 int (*fcn)
						 (osip_negotiation_ctx_t *,
						  char *, char *, int,
						  char *));
/**
 * Set the callback used to accept a codec during a negotiation.
 * This callback is called once each time we need to accept a codec.
 * @param fcn The callback.
 */
  int
    osip_negotiation_set_fcn_accept_video_codec (osip_negotiation_t *,
						 int (*fcn)
						 (osip_negotiation_ctx_t *,
						  char *, char *, int,
						  char *));
/**
 * Set the callback used to accept a codec during a negotiation.
 * This callback is called once each time we need to accept a codec.
 * @param fcn The callback.
 */
  int
    osip_negotiation_set_fcn_accept_other_codec (osip_negotiation_t *,
						 int (*fcn)
						 (osip_negotiation_ctx_t *,
						  char *, char *, char *,
						  char *));
/**
 * Set the callback for setting the port number ('m' field) in a local SDP packet.
 * This callback is called once each time a 'm' line is accepted.
 * @param fcn The callback.
 */
  int osip_negotiation_set_fcn_get_audio_port (osip_negotiation_t *,
					       char
					       *(*fcn) (osip_negotiation_ctx_t
							*, int));
/**
 * Set the callback for setting the port number ('m' field) in a local SDP packet.
 * This callback is called once each time a 'm' line is accepted.
 * @param fcn The callback.
 */
  int osip_negotiation_set_fcn_get_video_port (osip_negotiation_t *,
					       char
					       *(*fcn) (osip_negotiation_ctx_t
							*, int));
/**
 * Set the callback for setting the port number ('m' field) in a local SDP packet.
 * This callback is called once each time a 'm' line is accepted.
 * @param fcn The callback.
 */
  int osip_negotiation_set_fcn_get_other_port (osip_negotiation_t *,
					       char
					       *(*fcn) (osip_negotiation_ctx_t
							*, int));

/**
 * Start the automatic negotiation for a UA
 * NOTE: You can previously set context->mycontext to point to your
 * personal context. This way you'll get access to your personal context
 * in the callback and you can easily take the correct decisions.
 * After this method is called, the negotiation will happen and
 * callbacks will be called. You can modify, add, remove SDP fields,
 * and accept and refuse the codec from your preferred list by using
 * those callbacks.
 * Of course, after the negotiation happen, you can modify the
 * SDP packet if you wish to improve it or just refine some attributes.
 * @param ctx The context holding the remote SDP offer.
 */
  int osip_negotiation_ctx_execute_negotiation (osip_negotiation_t *,
						osip_negotiation_ctx_t * ctx);

/** Put the SDP message on hold in outgoing invite
 * @param ctx The element to work on.
 * @param sdp The sdp message to build.
 * @param audio_port The port for audio stream.
 * @param video_port The port for video stream.
 */
  int osip_negotiation_sdp_build_offer (osip_negotiation_t *,
					osip_negotiation_ctx_t * ctx,
					sdp_message_t ** sdp,
					char *audio_port, char *video_port);
/**
 *@internal
 */
  int __osip_negotiation_sdp_build_offer (osip_negotiation_t *,
					  osip_negotiation_ctx_t * ctx,
					  sdp_message_t ** sdp,
					  char *audio_port, char *video_port,
					  char *audio_codec,
					  char *video_codec);

/** Put the SDP message on hold in outgoing invite
 * @param sdp The sdp message to modify.
 */
  int osip_negotiation_sdp_message_put_on_hold (sdp_message_t * sdp);

/** Put the SDP message off hold in outgoing invite
 * @param sdp The sdp message to modify.
 */
  int osip_negotiation_sdp_message_put_off_hold (sdp_message_t * sdp);

/**
 * @internal
 * @}
 */


#ifdef __cplusplus
}
#endif

#endif /*_SDP_NEGOC_H_ */
