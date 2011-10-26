#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

The remote printer has no password set

Description :


The remote printer has no password set. This allows anyone 
to change its IP or potentially to intercept print jobs sent
to it.

Solution : 

Telnet to this printer and set a password.

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:L/Au:NR/C:P/A:C/I:P/B:N)";

if(description)
{
 script_id(10172);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-1061");

 name["english"] = "Passwordless HP LaserJet";
 script_name(english:name["english"]);
 script_description(english:desc["english"]);
 summary["english"] = "Notifies that the remote printer has no password";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999 - 2006 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("telnetserver_detect_type_nd_version.nasl");
 script_require_ports(23);
 exit(0);
}

#
# The script code starts here
#

include('telnet_func.inc');
passwordless = 0;
port = 23;

banner = get_telnet_banner(port:port);
if ( "JetDirect" >!< banner ) exit(0);
 
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = telnet_negotiate(socket:soc);
  if("JetDirect" >< buf){
  	set_kb_item(name:"devices/hp_printer", value:TRUE);
  	buf += recv(socket:soc, length:1024);
	buf = tolower(buf);
	if("password" >!< buf && "username" >!< buf)  passwordless = 1;
	}
 else {
  	buf += recv(socket:soc, length:1024, timeout:2);
	if("JetDirect" >< buf)
	{
	 set_kb_item(name:"devices/hp_printer", value:TRUE);
	 if("password" >!< buf && "username" >!< buf) passwordless = 1;
 	}
      }
   if ( passwordless ) {
# Send '/' to retrieve the current settings
        request = string ("/\r\n");
	send(socket:soc, data:request);
	info = recv(socket:soc, length: 1024);
	if ( "JetDirect" >< info ) {
		report = desc["english"] + '\n\nPlugin output :\n\nIt was possible to obtain the remote printer configuration : ' + info;
	} else {
		report = desc["english"];
        }
	security_hole(port:port, data:report);
  }
  close(soc);
 }
}
