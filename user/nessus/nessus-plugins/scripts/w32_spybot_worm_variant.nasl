#
# This script was written by Jorge E Rodriguez <KPMG>
#
# 
#
# 	- check the system for infected w32.spybot.fbg
#	- script id
#	- cve id
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(15520);
 script_version ("$Revision: 1.13 $");
 
 name["english"] = "w32.spybot.fcd worm infection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote system is infected with a variant of the worm w32.spybot.fcd. 

Infected systems will scan systems that are vulnerable in the same subnet
in order to attempt to spread.

This worm also tries to do DDoS against targets in the Internet.

Solution : ensure all MS patches are applied as well as the latest AV 
definitions.

See also : http://securityresponse.symantec.com/avcenter/venc/data/w32.spybot.fcd.html
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detects if w32.spybot.fcd is installed on the remote host";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 jorge rodriguez");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "os_fingerprint.nasl");
 script_require_ports(113);
 script_exclude_keys('fake_identd/113');
 exit(0);
}

#
# The script code starts here
#
include('misc_func.inc');

os = get_kb_item("Host/OS/icmp");
if ( os && "Windows" >!< os ) exit(0);

if (get_kb_item('fake_identd/113')) exit(0);

if(get_port_state(113))
{
 soc = open_sock_tcp(113);
 if(soc)
 {
  req = string("GET\r\n");
  send(socket:soc, data:req);
  r = recv(socket:soc, length:16000);
  if(" : USERID : UNIX :" >< r) {
	if ( "GET : USERID : UNIX :" >< r ) exit(0);
	security_hole(113);
	if (service_is_unknown(port: 113))
	  register_service(port: 113, proto: 'fake-identd');
	set_kb_item(name: 'fake_identd/113', value: TRUE);
	}
  close(soc);
 }
}
