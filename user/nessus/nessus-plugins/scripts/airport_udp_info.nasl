#
# (C) Tenable Network Security
#


 desc["english"] = "
The remote host is an Airport, Airport Extreme or Airport Express 
wireless access point.

It is possible to gather information about the remote base station
(such as its connection type or connection time) by sending packets 
to UDP port 192. 

An attacker connected to this network may also use this protocol to 
force the base station to disconnect from the network if it is 
using PPPoE, thus causing a denial of service for the other users.


Solution :

Filter incoming traffic to this port, make sure only authorized hosts
can connect to the wireless network this base station listens on.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:N/A:C/I:N/B:A)";

if(description)
{
 script_id(20345);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Airport Administrative Traffic Detection (192/udp)";
 script_name(english:name["english"]);
 


 script_description(english:desc["english"]);
 
 summary["english"] = "Sends a message to UDP port 192";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 exit(0);
}


include("byte_func.inc");

Airport_Status_Request = raw_string(0x08, 0x01, 0x03, 0x10);
Airport_Connection_Time_Offset = 34;
Airport_Connection_Type_Offset = 6;

Airport_Connection_Type_DHCP_or_STATIC   = 0x01;
Airport_Connection_Type_PPTP   = 0x04;


soc = open_sock_udp(192);
send(socket:soc, data:Airport_Status_Request);
r = recv(socket:soc, length:4096);
if ( ! r || strlen(r) < 38 ) exit(0);

connType = getbyte(blob:r, pos:Airport_Connection_Type_Offset);

l = getdword(blob:r, pos:Airport_Connection_Time_Offset);
days = l / (3600*24);
l    -= ( days * 3600 * 24 );
hours = l / 3600;
l    -= ( hours * 3600 );
mins  = l / 60;
l    -= ( mins * 60 );
secs  = l;



report = desc["english"] + string("\n\nPlugin output:\n\n") +  " - The station has been connected to the network for " + days + " days " + hours + "h" + mins + "m" + secs + "s";


if ( connType == Airport_Connection_Type_PPTP )
   report += '\n - The station is connected to the network via PPTP\n';
else if ( connType == Airport_Connection_Type_DHCP_or_STATIC )
   report += '\n - The station is connected to the network via DHCP or a static IP address\n';

security_note(port:192, data:report, proto:"udp");




