#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
# modded by John Jackson <jjackson@attrition.org> to pull hostname
#
# changes by rd : more verbose report on hostname
#
# changes by Tenable Network Security: new detection code
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10006);
 script_version ("$Revision: 1.19 $");
 name["english"] = "pcAnywhere";
 script_name(english:name["english"]);

 
 desc["english"] = "
pcAnywhere is running on this port.

Solution : Disable this service if you do not use it.
Risk factor : None";
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence pcAnywhere";
 script_summary(english:summary["english"]);


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999 Mathieu Perrin");

 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");


exit(0);
}


#
# The script code starts here
#

port = 5632;
if (!get_port_state(port))
  exit (0);

soc = open_sock_udp(port);
if (!soc) exit(0);

send (socket:soc, data:"ST");
buf = recv(socket:soc, length:2);
if ("ST" >< buf)
  security_note (port);
