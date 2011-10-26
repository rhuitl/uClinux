#
# oracle_tnslsnr_security.nasl - NASL script to do a TNS STATUS 
# command against the Oracle tnslsnr and grep out "SECURITY=OFF"
#
# James W. Abendschan <jwa@jammed.com>
#


if (description)
{
	script_id(10660);
 	script_version ("$Revision: 1.13 $");
	script_name(english: "Oracle tnslsnr security");
	script_description(english: 
"The remote Oracle tnslsnr has no password assigned.
An attacker may use this fact to shut it down arbitrarily,
thus preventing legitimate users from using it properly.

Solution:  use the lsnrctrl SET PASSWORD command to assign a password to, the tnslsnr.
Risk factor : High"

	);

	script_summary(english: "Determines if the Oracle tnslsnr has been assigned a password.");

	script_category(ACT_GATHER_INFO);
	script_family(english: "Databases");
	script_copyright(english: "James W. Abendschan <jwa@jammed.com> (GPL)");
	script_dependencie("oracle_tnslsnr_version.nasl");
        script_require_ports("Services/oracle_tnslsnr");
	exit(0);
}

include('global_settings.inc');

function tnscmd(sock, command)
{
	# construct packet
	
	command_length = strlen(command);
	packet_length = command_length + 58;

	# packet length - bytes 1 and 2

	plen_h = packet_length / 256;
	plen_l = 256 * plen_h;			# bah, no ( ) ?
	plen_l = packet_length - plen_h;

	clen_h = command_length / 256;
	clen_l = 256 * clen_h;
	clen_l = command_length - clen_l;


	packet = raw_string(
		plen_h, plen_l, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
		0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00, 
		0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01, 
		clen_h, clen_l, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x34, 0xe6, 0x00, 0x00, 
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, command
		);


	send (socket:sock, data:packet);
	r = recv(socket:sock, length:8192, timeout:5);

	return (r);
}


function oracle_tnslsnr_security(port)
{
	sock = open_sock_tcp(port);
	if (sock) 
	{
		cmd = "(CONNECT_DATA=(COMMAND=STATUS))";
		reply = tnscmd(sock:sock, command:cmd);
		close(sock);
		if ( ! reply ) return 0;

		if ("SECURITY=OFF" >< reply)
		{
			security_hole(port:port);
		}
		else
		{
			if ("SECURITY=ON" >< reply || "ERROR=(CODE=1169)" >< reply )
			{
				# FYI
				report = string
				(
				"This host is running a passworded Oracle tnslsnr.\n"
				);
				security_note(port:port, data:report);
			}
			else if ( "ERROR=(CODE=12618)" >< reply && report_verbosity == 2 )
			{
				report = string( "This host has an incompatible version of tnslsnr for the plugin. This cannot be checked.\n");
				security_note(port:port, data:report);
			}
		} 
	}	
}

# tnslsnr runs on different ports . . .

port = get_kb_item("Services/oracle_tnslsnr");
if ( isnull(port)) exit(0);

if(get_port_state(port))
 {
  oracle_tnslsnr_security(port:port);
 }

