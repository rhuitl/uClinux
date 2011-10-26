/* $Id */

/*
** Copyright (C) 2005 Sourcefire Inc.
**
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/


/*
 * SSH preprocessor
 * Author: Chris Sherwin
 * Contributors: Adam Keeton
 *
 *
 * Alert for Gobbles, CRC32, protocol mismatch (Cisco catalyst vulnerability),
 * and a SecureCRT vulnerability.  Will also alert if the client or server 
 * traffic appears to flow the wrong direction, or if packets appear 
 * malformed/spoofed.
 * 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif  /* HAVE_CONFIG_H */

#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "sf_snort_plugin_api.h"

#include "preprocids.h"
#include "spp_ssh.h"

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#endif
#include <stdlib.h>
#include <ctype.h>

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats sshPerfStats;
#endif

/*
 * Generator id. Define here the same as the official registry
 * in generators.h
 */
#define GENERATOR_SPP_SSH	128

/*
 * Function prototype(s)
 */
SSHData* GetSSHData( SFSnortPacket* );
static void SSHInit( u_char* );
static void DisplaySSHConfig();
static void FreeSSHData( void* );
static void  ParseSSHArgs( u_char* );
static void ProcessSSH( void*, void* );
static inline int CheckSSHPort( u_int16_t );
static int ProcessSSHProtocolVersionExchange( SSHData*, SFSnortPacket*, 
		u_int8_t, u_int8_t );
static int ProcessSSHKeyExchange( SSHData*, SFSnortPacket*, u_int8_t );
static int ProcessSSHKeyInitExchange( SSHData*, SFSnortPacket*, u_int8_t );

/* Ultimately calls SnortEventqAdd */
/* Arguments are: gid, sid, rev, classification, priority, message, rule_info */
#define ALERT(x,y) { _dpd.alertAdd(GENERATOR_SPP_SSH, x, 1, 0, 3, y, 0 ); }

/* Convert port value into an index for the ssh_config.ports array */
#define PORT_INDEX(port) port/8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1<<(port%8)

/*
 * SSH preprocessor global configuration structure.
 */
static SSHConfig ssh_config =
	{
		0, 				                /* Autodetection */
		SSH_DEFAULT_MAX_ENC_PKTS, 	    /* Max enc pkts */
		SSH_DEFAULT_MAX_CLIENT_BYTES,   /* Max client bytes */
		0,				                /* Disable rules  */
		SSH_ALERT_ALL,			        /* Enabled alerts */
	};

extern DynamicPreprocessorData _dpd;

/* Called at preprocessor setup time. Links preprocessor keyword
 * to corresponding preprocessor initialization function.
 *
 * PARAMETERS:	None.
* 
 * RETURNS:	Nothing.
 *
 */
void SetupSSH()
{
	/* Link preprocessor keyword to initialization function 
 	 * in the preprocessor list.
 	 */
	_dpd.registerPreproc( "ssh", SSHInit );
}

/* Initializes the SSH preprocessor module and registers
 * it in the preprocessor list.
 * 
 * PARAMETERS:  
 *
 * argp:        Pointer to argument string to process for config
 *                      data.
 *
 * RETURNS:     Nothing. 
 */
static  void
SSHInit( u_char* argp )
{
    if(!_dpd.streamAPI) 
    {
        DynamicPreprocessorFatalMessage("SetupSSH(): The Stream preprocessor must be enabled.\n");
    }

	_dpd.addPreproc( ProcessSSH, PRIORITY_APPLICATION, PP_SSH );

	ParseSSHArgs( argp );

#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc("ssh", (void *)&sshPerfStats, 0, _dpd.totalPerfStats);
#endif
}

/* Parses and processes the configuration arguments 
 * supplied in the SSH preprocessor rule.
 *
 * PARAMETERS: 
 *
 * argp:        Pointer to string containing the config arguments.
 * 
 * RETURNS:     Nothing.
 */
static void 
ParseSSHArgs( u_char* argp )
{
	char* cur_tokenp = NULL;
	char* argcpyp = NULL;
    int port;
    
    /* Set up default port to listen on */
    ssh_config.ports[ PORT_INDEX( 22 ) ] |= CONV_PORT(22);

	/* Sanity check(s) */
	if ( !argp )
	{
        DisplaySSHConfig();
		return;
	}

	argcpyp = strdup( (char*) argp );

	if ( !argcpyp )
	{
        DynamicPreprocessorFatalMessage("Could not allocate memory to parse SSH options.\n");
		return;
	}

	cur_tokenp = strtok( argcpyp, " ");

	while ( cur_tokenp )
	{
		if ( !strcmp( cur_tokenp, SSH_SERVERPORTS_KEYWORD ))
		{
            /* If the user specified ports, remove '22' for now since 
             * it now needs to be set explicitely. */
            ssh_config.ports[ PORT_INDEX( 22 ) ] = 0;
            
			/* Eat the open brace. */
			cur_tokenp = strtok( NULL, " ");
			if (( !cur_tokenp ) || ( cur_tokenp[0] != '{' ))
			{
                DynamicPreprocessorFatalMessage("Bad value specified for %s.\n",
                                                SSH_SERVERPORTS_KEYWORD);
                free(argcpyp);
                return;
			}

			cur_tokenp = strtok( NULL, " ");
			while (( cur_tokenp ) && ( cur_tokenp[0] != '}' ))
			{
				if ( !isdigit( cur_tokenp[0] ))
				{
                    DynamicPreprocessorFatalMessage("Bad port %s.\n", cur_tokenp );
                    free(argcpyp);
                    return;
				}
				else
				{
                    port = atoi( cur_tokenp );
                    if( port < 0 || port > MAX_PORTS ) 
                    {
                        DynamicPreprocessorFatalMessage("Port value illegitimate: %s\n", cur_tokenp);
                        free(argcpyp);
                        return;
                    }
                    
                    ssh_config.ports[ PORT_INDEX( port ) ] |= CONV_PORT(port);
				}

				cur_tokenp = strtok( NULL, " ");
			}
				
		}
		else if ( !strcmp( cur_tokenp, SSH_AUTODETECT_KEYWORD ))
		{
			ssh_config.AutodetectEnabled++;
		}
		else if ( !strcmp( cur_tokenp, SSH_MAX_ENC_PKTS_KEYWORD ))
		{
			cur_tokenp = strtok( NULL, " ");
			if (( !cur_tokenp ) || !isdigit(cur_tokenp[0]) )
			{
				_dpd.logMsg("Bad value specified for %s."
					"Reverting to default value %d. ",
					SSH_MAX_ENC_PKTS_KEYWORD, 
					SSH_DEFAULT_MAX_ENC_PKTS );
			}
			else
			{
				ssh_config.MaxEncryptedPackets = (u_int16_t)
						atoi( cur_tokenp );
			}
		}
		else if (!strcmp( cur_tokenp, SSH_MAX_CLIENT_BYTES_KEYWORD ))
		{
			cur_tokenp = strtok( NULL, " ");
			if (( !cur_tokenp ) || !isdigit(cur_tokenp[0]) )
			{
				_dpd.logMsg("Bad value specified for %s."
					"Reverting to default value %d. ",
					SSH_MAX_CLIENT_BYTES_KEYWORD, 
					SSH_DEFAULT_MAX_CLIENT_BYTES );
			}
			else
			{
				ssh_config.MaxClientBytes = (u_int16_t)
						atoi( cur_tokenp );
			}
		}
		else if ( !strcmp( cur_tokenp, SSH_DISABLE_GOBBLES_KEYWORD ))
		{
			ssh_config.EnabledAlerts &= ~SSH_ALERT_GOBBLES;
		}
		else if ( !strcmp( cur_tokenp, SSH_DISABLE_CRC32_KEYWORD ))
		{
			ssh_config.EnabledAlerts &= ~SSH_ALERT_CRC32;
		}
		else if ( 
		   !strcmp( cur_tokenp, SSH_DISABLE_SECURECRT_KEYWORD ))
		{
			ssh_config.EnabledAlerts &= ~SSH_ALERT_SECURECRT;
		}
		else if ( 
		   !strcmp( cur_tokenp, SSH_DISABLE_PROTOMISMATCH_KEYWORD ))
		{
			ssh_config.EnabledAlerts &= ~SSH_ALERT_PROTOMISMATCH;
		}
		else if ( 
		   !strcmp( cur_tokenp, SSH_DISABLE_WRONGDIR_KEYWORD ))
		{
			ssh_config.EnabledAlerts &= ~SSH_ALERT_WRONGDIR;
		}
		else if ( !strcmp( cur_tokenp, SSH_DISABLE_RULES_KEYWORD ))
		{
			ssh_config.DisableRules++;	
		} 
        else if( !strcmp( cur_tokenp, SSH_DISABLE_PAYLOAD_SIZE )) 
        {
            ssh_config.EnabledAlerts &= ~SSH_ALERT_PAYSIZE;
        }
        else if( !strcmp( cur_tokenp, SSH_DISABLE_UNRECOGNIZED_VER ))
        {
            ssh_config.EnabledAlerts &= ~SSH_ALERT_UNRECOGNIZED;
        }
        else
        {
            DynamicPreprocessorFatalMessage("Invalid argument: %s\n", cur_tokenp);
    		return;
        }

		cur_tokenp = strtok( NULL, " " );
	}

	DisplaySSHConfig();
    free(argcpyp);
}

/* Display the configuration for the SSH preprocessor. 
 * 
 * PARAMETERS:	None.
 *
 * RETURNS: Nothing.
 */
static void
DisplaySSHConfig()
{
    int index;
    int newline;
    
	SSHPortNode* cur_nodep = NULL;

	_dpd.logMsg("SSH config: \n");
	_dpd.logMsg("    Autodetection: %s\n", 
			ssh_config.AutodetectEnabled ? 
			"ENABLED":"DISABLED");
	_dpd.logMsg("    GOBBLES Alert: %s\n",
			ssh_config.EnabledAlerts & SSH_ALERT_GOBBLES ?
			"ENABLED" : "DISABLED" );
	_dpd.logMsg("    SSH1 CRC32 Alert: %s\n",
			ssh_config.EnabledAlerts & SSH_ALERT_CRC32 ?
			"ENABLED" : "DISABLED" );

	_dpd.logMsg("    Server Version String Overflow Alert: %s\n",
			ssh_config.EnabledAlerts & SSH_ALERT_SECURECRT ?
			"ENABLED" : "DISABLED" );
	_dpd.logMsg("    Protocol Mismatch Alert: %s\n",
			ssh_config.EnabledAlerts & SSH_ALERT_PROTOMISMATCH?
			"ENABLED" : "DISABLED" );
	_dpd.logMsg("    Bad Message Direction Alert: %s\n",
			ssh_config.EnabledAlerts & SSH_ALERT_WRONGDIR ?
			"ENABLED" : "DISABLED" );
	_dpd.logMsg("    Bad Payload Size Alert: %s\n",
			ssh_config.EnabledAlerts & SSH_ALERT_PAYSIZE ?
			"ENABLED" : "DISABLED" );
	_dpd.logMsg("    Unrecognized Version Alert: %s\n",
			ssh_config.EnabledAlerts & SSH_ALERT_UNRECOGNIZED ?
			"ENABLED" : "DISABLED" );
	_dpd.logMsg("    Max Encrypted Packets: %d %s \n", 
			ssh_config.MaxEncryptedPackets, 
			ssh_config.MaxEncryptedPackets 
			    == SSH_DEFAULT_MAX_ENC_PKTS ?
			    "(Default)" : "" );

	if ( ssh_config.EnabledAlerts & 
		(SSH_ALERT_GOBBLES | SSH_ALERT_CRC32))
	{
		_dpd.logMsg("    MaxClientBytes: %d %s \n",   
			ssh_config.MaxClientBytes, 
			ssh_config.MaxClientBytes
			    == SSH_DEFAULT_MAX_CLIENT_BYTES ?
			    "(Default)" : "" );
	}

    /* Traverse list, printing ports, 5 per line */
    newline = 1;
	_dpd.logMsg("    Ports:\n"); 
    for(index = 0; index < MAX_PORTS; index++) 
    {
        if( ssh_config.ports[ PORT_INDEX(index) ] & CONV_PORT(index) )
        {
    	    _dpd.logMsg("\t%d", index);
            if ( !((newline++)% 5) )
            {
    	        _dpd.logMsg("\n");
            }
        }
    }
	_dpd.logMsg("\n");
}

/* Main runtime entry point for SSH preprocessor. 
 * Analyzes SSH packets for anomalies/exploits. 
 * 
 * PARAMETERS:
 *
 * packetp:    Pointer to current packet to process. 
 * contextp:    Pointer to context block, not used.
 *
 * RETURNS:     Nothing.
 */
static void
ProcessSSH( void* ipacketp, void* contextp )
{
	SSHData* sessp = NULL;
	u_int8_t source = 0;
	u_int8_t dest = 0;
	u_int8_t known_port = 0;
	u_int8_t direction; 
	SFSnortPacket* packetp;
    PROFILE_VARS;

	packetp = (SFSnortPacket*) ipacketp;

	/* Make sure this preprocessor should run. */
	if (( !packetp ) ||
	    ( !packetp->payload ) ||
	    ( !packetp->payload_size ) ||
	    ( !packetp->ip4_header ) ||
	    ( !packetp->tcp_header ) ||
        /* check if we're waiting on stream reassembly */
        ( packetp->flags & FLAG_STREAM_INSERT))
	{
 		return;
	} 

    /* If we picked up mid-stream do not process further */
    if ( _dpd.streamAPI->get_session_flags(
            packetp->stream_session_ptr) & SSNFLAG_MIDSTREAM )
    {
        return;
    }

	/* If not doing autodetection, check the ports to make sure this is 
	 * running on an SSH port, otherwise no need to examine the traffic.
	 */
	source = CheckSSHPort( packetp->src_port );
	dest = CheckSSHPort( packetp->dst_port );

	if ( !ssh_config.AutodetectEnabled && !source && !dest )
	{
		/* Not one of the ports we care about. */
		return;
	}

    PREPROC_PROFILE_START(sshPerfStats);

	/* See if a known server port is involved. */
	known_port = ( source || dest ? 1 : 0 );

	/* Get the direction of the packet. */
	direction = ( (packetp->flags & FLAG_FROM_SERVER ) ? 
			SSH_DIR_FROM_SERVER : SSH_DIR_FROM_CLIENT );

	/* Check the stream session. If it does not currently
	 * have our SSH data-block attached, create one.
	 */
	sessp = GetSSHData( packetp );

	if ( !sessp )
	{
		/* Could not get/create the session data for this packet. */
        PREPROC_PROFILE_END(sshPerfStats);
		return;
	}

	if ( !(sessp->state_flags & SSH_FLG_SESS_ENCRYPTED ))
	{
		/* If server and client have not performed the protocol 
		 * version exchange yet, must look for version strings.
	 	 */
		if ( (sessp->state_flags & SSH_FLG_BOTH_IDSTRING_SEEN)
			!= SSH_FLG_BOTH_IDSTRING_SEEN )
		{
			if ( ProcessSSHProtocolVersionExchange( sessp, 
					packetp, direction, known_port ) ==
				SSH_FAILURE )
			{
				/*Error processing protovers exchange msg */
			}

            PREPROC_PROFILE_END(sshPerfStats);
			return;
		}

		/* Expecting to see the key init exchange at this point 
		 * (in SSH2) or the actual key exchange if SSH1 
		 */
		if ((( sessp->state_flags & SSH_FLG_V1_KEYEXCH_DONE )
			!= SSH_FLG_V1_KEYEXCH_DONE ) &&
		     ((sessp->state_flags & SSH_FLG_V2_KEXINIT_DONE )
			!= SSH_FLG_V2_KEXINIT_DONE ))
		{
		    ProcessSSHKeyInitExchange( sessp, packetp, direction );
			
            PREPROC_PROFILE_END(sshPerfStats);
			return;
		}

		/* If SSH2, need to process the actual key exchange msgs.
		 * The actual key exchange type was negotiated in the
		 * key exchange init msgs. SSH1 won't arrive here.
		 */
		ProcessSSHKeyExchange( sessp, packetp, direction );
	}
	else
	{
		/* Traffic on this session is currently encrypted. 
		 * Two of the major SSH exploits, SSH1 CRC-32 and
 		 * the GOBBLES attack occur within the encrypted 
		 * portion of the SSH session. Therefore, the only
		 * way to detect these attacks is by examining 
		 * amounts of data exchanged for anomalies.
  		 */
		sessp->num_enc_pkts++;

		if ( sessp->num_enc_pkts <= ssh_config.MaxEncryptedPackets )
		{
			if ( direction == SSH_DIR_FROM_CLIENT )
			{
			   sessp->num_client_bytes += packetp->payload_size;

			   if ( sessp->num_client_bytes >= 
				ssh_config.MaxClientBytes ) 
			   {
				/* Probable exploit in progress.*/
				if (sessp->version == SSH_VERSION_1) 
				{
					if ( ssh_config.EnabledAlerts & SSH_ALERT_CRC32 )
					{
        			    ALERT(SSH_EVENT_CRC32, SSH_EVENT_CRC32_STR);

			            _dpd.streamAPI->stop_inspection( 
            				packetp->stream_session_ptr, 
            				packetp, 
            				SSN_DIR_BOTH, -1, 0 ); 
					}
				}
				else
				{
					if ( ssh_config.EnabledAlerts & SSH_ALERT_GOBBLES )
					{
						ALERT(SSH_EVENT_GOBBLES, SSH_EVENT_GOBBLES_STR);

			            _dpd.streamAPI->stop_inspection( 
            				packetp->stream_session_ptr, 
            				packetp, 
            				SSN_DIR_BOTH, -1, 0 ); 
					}
				}
			   }
			}
			else
			{
				/* 
				 * Have seen a server response, so 
				 * this appears to be a valid exchange.
				 * Reset suspicious byte count to zero.
				 */
				sessp->num_client_bytes = 0;
			}
		}
		else
		{
			/* Have already examined more than the limit
			 * of encrypted packets. Both the Gobbles and
			 * the CRC32 attacks occur during authentication
			 * and therefore cannot be used late in an 
			 * encrypted session. For performance purposes,
			 * stop examining this session.
			 */
			_dpd.streamAPI->stop_inspection( 
				packetp->stream_session_ptr, 
				packetp, 
				SSN_DIR_BOTH, -1, 0 ); 
           
		}

	}
    PREPROC_PROFILE_END(sshPerfStats);
}

/* Retrieves the SSH data block registered with the stream 
 * session associated w/ the current packet. If none exists,
 * allocates it and registers it with the stream API. 
 *
 * PARAMETERS:
 *
 * packetp:	Pointer to the packet from which/in which to
 * 		retrieve/store the SSH data block.
 *
 * RETURNS:	Pointer to an SSH data block, upon success.
 *		NULL, upon failure.
 */
SSHData* 
GetSSHData( SFSnortPacket* packetp )
{
	SSHData* datap = NULL;

	/* Sanity check(s) */
	if (( !packetp ) || ( !packetp->stream_session_ptr ))
	{
		return NULL;
	}

	/* Attempt to get a previously allocated SSH block. If none exists,
 	 * allocate and register one with the stream layer.
	 */
	datap = _dpd.streamAPI->get_application_data( 
			packetp->stream_session_ptr, 
			PP_SSH );

	if ( !datap )
	{
		datap = malloc( sizeof( SSHData ));

		if ( !datap )
			return NULL;

		/* Initialize to known state. */
		bzero( datap, sizeof( SSHData ));

		/*Register the new SSH data block in the stream session. */
		_dpd.streamAPI->set_application_data( 
				packetp->stream_session_ptr, 
				PP_SSH, datap, FreeSSHData );
	}

	return datap;
}

/* Registered as a callback with our SSH data blocks when 
 * they are added to the underlying stream session. Called
 * by the stream preprocessor when a session is about to be
 * destroyed.
 * 
 * PARAMETERS:
 *
 * idatap:	Pointer to the moribund data.
 *
 * RETURNS:	Nothing.
 */
static void
FreeSSHData( void* idatap )
{
	if ( idatap )
	{
		free( idatap );
	}
}

/* Validates given port as an SSH server port.
 *
 * PARAMETERS:
 *
 * port:	Port to validate.
 *
 * RETURNS:	SSH_TRUE, if the port is indeed an SSH server port.
 *		SSH_FALSE, otherwise.
 */
static inline int
CheckSSHPort( u_int16_t port )
{
    if ( ssh_config.ports[ PORT_INDEX(port) ] & CONV_PORT( port ) )
    {
        return SSH_TRUE;
    }

    return SSH_FALSE;
}

/* Checks if the string 'str' is 'max' bytes long or longer. 
 * Returns 0 if 'str' is less than or equal to 'max' bytes;
 * returns 1 otherwise.
*/
static inline int SSHCheckStrlen(char *str, int max) {
    while(*(str++) && max--) ;

    if(max > 0) return 0;   /* str size is <= max bytes */

    return 1;
}

/* Attempts to process current packet as a protocol version exchange
 * packet. This function will be called if either the client or server
 * protocol version message (or both) has not been sent.
 *
 * PARAMETERS:
 *
 * sessionp:    Pointer to SSH data for packet's session.
 * packetp:	Pointer to the packet to inspect.
 * direction: 	Which direction the packet is going.
 * known_port:  A pre-configured or default server port is involved.
 * 
 * RETURNS:	SSH_SUCCESS, if successfully processed a proto exch msg
 *		SSH_FAILURE, otherwise.
 */
static int
ProcessSSHProtocolVersionExchange( SSHData* sessionp, SFSnortPacket* packetp, 
	u_int8_t direction, u_int8_t known_port )
{
	char* version_stringp = (char*) packetp->payload;	
	u_int8_t version;

	/* Get the version. */
	if ( packetp->payload_size >= 6 && 
         !strncasecmp( version_stringp, "SSH-1.", 6))
	{
		if (( packetp->payload_size > 7 ) && ( version_stringp[6] == '9') 
			&& (version_stringp[7] == '9'))
		{
			/* SSH 1.99 which is the same as SSH2.0 */
			version = SSH_VERSION_2;
		}
		else
		{
			version = SSH_VERSION_1;
		}

		/* CAN-2002-0159 */
        /* Verify the version string is not greater than 
         * SSH_MAX_PROTOVERS_STRING. 
         * We've already verified the first 6 bytes, so we'll start
         * check from &version_string[6] */
        if( (ssh_config.EnabledAlerts & SSH_ALERT_SECURECRT ) &&
            /* First make sure the payload itself is sufficiently large */
             (packetp->payload_size > SSH_MAX_PROTOVERS_STRING) &&
            /* CheckStrlen will check if the version string up to 
             * SSH_MAX_PROTOVERS_STRING+1 since there's no reason to 
             * continue checking after that point*/
             (SSHCheckStrlen(&version_stringp[6], SSH_MAX_PROTOVERS_STRING-6)))
        {
            ALERT(SSH_EVENT_SECURECRT, SSH_EVENT_SECURECRT_STR);
        }
	}
	else if ( packetp->payload_size >= 6 && 
              !strncasecmp( version_stringp, "SSH-2.", 6))
	{
		version = SSH_VERSION_2;
	}
	else
	{
		/* Not SSH on SSH port, CISCO vulnerability */
		if ((direction == SSH_DIR_FROM_CLIENT) && 
			( known_port != 0 ) && 
			( ssh_config.EnabledAlerts & 
				SSH_ALERT_PROTOMISMATCH ))
		{
            ALERT(SSH_EVENT_PROTOMISMATCH, SSH_EVENT_PROTOMISMATCH_STR);
		}

		return SSH_FAILURE;
	}

	/* Saw a valid protocol exchange message. Mark the session
	 * according to the direction. 
	 */
	switch( direction )
	{
		case SSH_DIR_FROM_SERVER:
			sessionp->state_flags |= SSH_FLG_SERV_IDSTRING_SEEN;
			break;
		case SSH_DIR_FROM_CLIENT:
			sessionp->state_flags |= SSH_FLG_CLIENT_IDSTRING_SEEN;
			break;
	}

	sessionp->version = version;

	return SSH_SUCCESS;	
}

/* Called to process SSH1 key exchange or SSH2 key exchange init 
 * messages.  On failure, inspection will be continued, but the packet
 * will be alerted on, and ignored.
 *
 * PARAMETERS:
 *
 * sessionp:    Pointer to SSH data for packet's session.
 * packetp:	Pointer to the packet to inspect.
 * direction: 	Which direction the packet is going.
 * 
 * RETURN:	SSH_SUCCESS, if a valid key exchange message is processed 
 *		SSH_FAILURE, otherwise.
 */
static int 
ProcessSSHKeyInitExchange( SSHData* sessionp, SFSnortPacket* packetp, 
	u_int8_t direction )
{	
	SSH2Packet* ssh2packetp = NULL;

	if ( sessionp->version == SSH_VERSION_1 )
	{
		u_int32_t length;
		u_int8_t padding_length;
		u_int8_t message_type;

	    /* 
         * Validate packet payload.
         * First 4 bytes should have the SSH packet length, 
         * minus any padding.
         */
		if ( packetp->payload_size < 4 )
        {
            if(ssh_config.EnabledAlerts & SSH_ALERT_PAYSIZE)
            {
                ALERT(SSH_EVENT_PAYLOAD_SIZE, SSH_PAYLOAD_SIZE_STR);
            }

			return SSH_FAILURE;
        }

		/* 
		 * SSH1 key exchange is very simple and
 		 * consists of only two messages, a server
		 * key and a client key message.`
		 */
		length = ntohl( *((u_int32_t*) packetp->payload) );

	    /* Packet payload should be larger than length, due to padding. */
		if ( packetp->payload_size < length )
		{
            if(ssh_config.EnabledAlerts & SSH_ALERT_PAYSIZE)
            {   
                ALERT(SSH_EVENT_PAYLOAD_SIZE, SSH_PAYLOAD_SIZE_STR);
            }

			return SSH_FAILURE;
		}

		padding_length = (u_int8_t)(8 - (length % 8));

        /* 
         * With the padding calculated, verify payload is sufficiently large
         * to include the message type.
         */
        if ( packetp->payload_size < padding_length + 4 + 1)
        {
            if(ssh_config.EnabledAlerts & SSH_ALERT_PAYSIZE)
            {
                ALERT(SSH_EVENT_PAYLOAD_SIZE, SSH_PAYLOAD_SIZE_STR);
            }

			return SSH_FAILURE;
        }
        
		message_type = 
		     *( (u_int8_t*) (packetp->payload + padding_length + 4));

		switch( message_type )
		{
			case SSH_MSG_V1_SMSG_PUBLIC_KEY: 
				if ( direction == SSH_DIR_FROM_SERVER )
				{
					sessionp->state_flags |= 
						SSH_FLG_SERV_PKEY_SEEN;
				}
				else if ( ssh_config.EnabledAlerts & 
					SSH_ALERT_WRONGDIR )
				{
					/* Server msg not from server. */
                    ALERT(SSH_EVENT_WRONGDIR, SSH_EVENT_WRONGDIR_STR);
				}
				break;
			case SSH_MSG_V1_CMSG_SESSION_KEY:
				if ( direction == SSH_DIR_FROM_CLIENT )
				{
					sessionp->state_flags |= 
						SSH_FLG_CLIENT_SKEY_SEEN;
				}
				else if ( ssh_config.EnabledAlerts & 
					SSH_ALERT_WRONGDIR )
				{
					/* Client msg not from client. */ 
                    ALERT(SSH_EVENT_WRONGDIR, SSH_EVENT_WRONGDIR_STR);
				}
				break;
			default:
				/* Invalid msg type */
				break;
		}

		/* Once the V1 key exchange is done, remainder of 
		 * communications are encrypted.
		 */
		if ( (sessionp->state_flags & SSH_FLG_V1_KEYEXCH_DONE) ==
			SSH_FLG_V1_KEYEXCH_DONE )
		{
			sessionp->state_flags |= SSH_FLG_SESS_ENCRYPTED;
		}
	}
	else if ( sessionp->version == SSH_VERSION_2 )
	{
        /* We want to overlay the payload on our data packet struct,
         * so first verify that the payload size is big enough.
         * This may legitimately occur such as in the case of a 
         * retransmission.
         */
        if ( packetp->payload_size < sizeof(SSH2Packet) )
        {
			return SSH_FAILURE;
        }
        
		/* Overlay the SSH2 binary data packet struct on the packet */
		ssh2packetp = (SSH2Packet*) packetp->payload;
		if (( packetp->payload_size < SSH2_HEADERLEN + 1) || 
			( packetp->payload_size < ntohl(ssh2packetp->packet_length) ))
		{
			/* Invalid packet length. */

			return SSH_FAILURE;
		}

		switch ( packetp->payload[SSH2_HEADERLEN] )
		{
			case SSH_MSG_KEXINIT:
				sessionp->state_flags |= 
					(direction == SSH_DIR_FROM_SERVER ?
						SSH_FLG_SERV_KEXINIT_SEEN :
						SSH_FLG_CLIENT_KEXINIT_SEEN );
				break;
			default:
				/* Unrecognized message type. */
				break;
		}
	}
	else
	{
        if(ssh_config.EnabledAlerts & SSH_ALERT_UNRECOGNIZED)
        {
		    /* Unrecognized version. */
            ALERT(SSH_EVENT_VERSION, SSH_VERSION_STR);
        }

		return SSH_FAILURE;
	}
	
	return SSH_SUCCESS;
}

/* Called to process SSH2 key exchange msgs (key exch init msgs already
 * processed earlier). On failure, inspection will be continued, but the 
 * packet will be alerted on, and ignored.
 * 
 * PARAMETERS: 
 *
 * sessionp:    Pointer to SSH data for packet's session.
 * packetp:	Pointer to the packet to inspect.
 * direction: 	Which direction the packet is going.
 * 
 * RETURN:	SSH_SUCCESS, if a valid key exchange message is processed 
 *		SSH_FAILURE, otherwise.
 */
static int
ProcessSSHKeyExchange( SSHData* sessionp, SFSnortPacket* packetp, 
	u_int8_t direction )
{
	SSH2Packet* ssh2packetp = NULL;

    if ( packetp->payload_size < sizeof(SSH2Packet) )
    {
		/* Invalid packet length. */
		return SSH_FAILURE;
    }
        
	ssh2packetp = (SSH2Packet*) packetp->payload;

	if (( packetp->payload_size < SSH2_HEADERLEN + 1 ) || 
		( packetp->payload_size < ntohl(ssh2packetp->packet_length) ))
	{

        if(ssh_config.EnabledAlerts & SSH_ALERT_PAYSIZE)
        {
		    /* Invalid packet length. */
            ALERT(SSH_EVENT_PAYLOAD_SIZE, SSH_PAYLOAD_SIZE_STR);
        }

		return SSH_FAILURE;
	}

	switch( packetp->payload[SSH2_HEADERLEN] )
	{
		case SSH_MSG_KEXDH_INIT:
			if ( direction == SSH_DIR_FROM_CLIENT )
			{
				sessionp->state_flags |= 
					SSH_FLG_KEXDH_INIT_SEEN;
			}
			else if ( ssh_config.EnabledAlerts & 
					SSH_ALERT_WRONGDIR )
			{
				/* Client msg from server. */
                ALERT(SSH_EVENT_WRONGDIR, SSH_EVENT_WRONGDIR_STR);
			}
			break;
		case SSH_MSG_KEXDH_REPLY:
			if ( direction == SSH_DIR_FROM_SERVER )
			{
				/* KEXDH_REPLY has the same msg
			 	 * type as the new style GEX_REPLY
				 */
				sessionp->state_flags |= 
					SSH_FLG_KEXDH_REPLY_SEEN | 
					SSH_FLG_GEX_REPLY_SEEN;

			}
			else if ( ssh_config.EnabledAlerts & 
					SSH_ALERT_WRONGDIR )
			{
				/* Server msg from client. */
                ALERT(SSH_EVENT_WRONGDIR, SSH_EVENT_WRONGDIR_STR);
			}
			break;
		case SSH_MSG_KEXDH_GEX_REQ:
			if ( direction == SSH_DIR_FROM_CLIENT )
			{
				sessionp->state_flags |= 
					SSH_FLG_GEX_REQ_SEEN;
			}
			else if ( ssh_config.EnabledAlerts & 
					SSH_ALERT_WRONGDIR )
			{
				/* Server msg from client. */
                ALERT(SSH_EVENT_WRONGDIR, SSH_EVENT_WRONGDIR_STR);
			}
			break;
		case SSH_MSG_KEXDH_GEX_GRP:
			if ( direction == SSH_DIR_FROM_SERVER )
			{
				sessionp->state_flags |= 
					SSH_FLG_GEX_GRP_SEEN;
			}
			else if ( ssh_config.EnabledAlerts & 
					SSH_ALERT_WRONGDIR )
			{
				/* Client msg from server. */
                ALERT(SSH_EVENT_WRONGDIR, SSH_EVENT_WRONGDIR_STR);
			}
			break;
		case SSH_MSG_KEXDH_GEX_INIT:
			if ( direction == SSH_DIR_FROM_CLIENT )
			{
				sessionp->state_flags |= 
					SSH_FLG_GEX_INIT_SEEN;
			}
			else if ( ssh_config.EnabledAlerts & 
					SSH_ALERT_WRONGDIR )
			{
				/* Server msg from client. */
                ALERT(SSH_EVENT_WRONGDIR, SSH_EVENT_WRONGDIR_STR);
			}
			break;
		case SSH_MSG_NEWKEYS:
			/* This message is required to complete the
			 * key exchange. Both server and client should
			 * send one, but as per Alex Kirk's note on this, 
			 * in some implementations the server does not
			 * actually send this message. So receving a new 
			 * keys msg from the client is sufficient.
			 */
			if ( direction == SSH_DIR_FROM_CLIENT )
			{
				sessionp->state_flags |= SSH_FLG_NEWKEYS_SEEN;
			}
			break;
		default:
			/* Unrecognized message type. */
			break;
	}

	/* If either an old-style or new-style Diffie Helman exchange
	 * has completed, the session will enter encrypted mode. 
	 */
	if (( (sessionp->state_flags &
		SSH_FLG_V2_DHOLD_DONE) == SSH_FLG_V2_DHOLD_DONE ) 
		|| ( (sessionp->state_flags & 
			SSH_FLG_V2_DHNEW_DONE) == SSH_FLG_V2_DHNEW_DONE ))
	{
		sessionp->state_flags |= 
			SSH_FLG_SESS_ENCRYPTED;
	}

	return SSH_SUCCESS;
}
