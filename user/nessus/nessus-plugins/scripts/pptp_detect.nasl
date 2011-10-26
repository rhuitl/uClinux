#
# (C) Tenable Network Security
#
 desc["english"] = "
Synopsis :

A VPN server is listening on the remote port.

Description :

The remote host is running a PPTP (Point-to-Point Tunneling Protocol)
server. It allows users to set up a tunnel between their host and the
network the remote host is attached to.

Make sure the use of this software is done in accordance with your 
corporate security policy.

Solution :

Disable this software if you do not use it

Risk factor :

None";





if (description)
{
 script_id(10622);
 script_version ("$Revision: 1.14 $");
 script_name(english:"PPTP Detection"); 
 script_description(english:desc["english"]);
 script_summary(english:"Connects to port 1723 to determine if a PPTP server is listening");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_require_ports(1723);
 exit(0);
}

port=1723;
include("misc_func.inc");
include("byte_func.inc");

if ( ! get_port_state(port) ) exit(0);

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

pptp_head =	mkword(1) +			# Message Type
        	mkdword(0x1a2b3c4d) +		# Cookie
 		mkword(1) +			# Control type (Start-Control-Connection-Request)
		mkword(0) +			# Reserved
		mkword(0x0100) +		# Protocol Version (1.0)
  		mkword(0) +			# Reserved
		mkdword(1) +			# Framing Capabilities
		mkdword(1) +			# Bearer capabilities
		mkword(0);			# Maximum channels
pptp_vendor = mkword(NASL_LEVEL) +		# Firmware revision 
	      mkpad(64) +			# Hostname 
	      mkpad(64);			# Vendor


pptp = mkword(strlen(pptp_head) + strlen(pptp_vendor) + 2) + pptp_head + pptp_vendor;

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:pptp);
r = recv(socket:soc, length:2);
if ( ! r || strlen(r) != 2 ) exit(0);
l = getword(blob:r, pos:0); 
r += recv(socket:soc, length:l - 2, min:l - 2);
if ( strlen(r) != l ) exit(0);
if ( strlen(r) < strlen(pptp_head) + strlen(pptp_vendor) ) exit(0);

cookie = getdword(blob:r, pos:4);
if ( cookie != 0x1a2b3c4d ) exit(0);

ptr = strlen(pptp_head) + 2;
firmware = getword(blob:r, pos:ptr);
ptr += 2;
rhostname = substr(r , ptr, ptr + 63);
for ( i = 0 ; ord(rhostname[i]) != 0 && i < 64;  i ++ )
 {
  hostname += rhostname[i];
 }

ptr += 64;
rvendor   = substr(r, ptr, ptr + 63);
for ( i = 0 ; ord(rvendor[i]) != 0 && i < 64;  i ++ )
 {
  vendor += rvendor[i];
 }

report = desc["english"];

if ( firmware != 0 || strlen(vendor) || strlen(hostname))
{
 report += '\n\nPlugin output :\n\n';
 report += 'It was possible to extract the following information from the remote PPTP server :\n';
 if ( firmware != 0 )
 	report += 'Firmware Version : ' + firmware + '\n';
 if ( strlen(vendor) != 0 )
 	report += 'Vendor Name : ' + vendor + '\n';
 if ( strlen(hostname) != 0 )
 	report += 'Host name : ' + hostname + '\n';
}


register_service(port:port, proto:"pptp");
security_note(port:port, data:report);
