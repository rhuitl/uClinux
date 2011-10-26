#
# Copyright (C) 2004 Tenable Network Security
#
#
# rev 1.7: fixes a bug introduced in rev 1.6 spotted by Phil Bordelon 
# rev 1.6: MyDoom.B detection
#

if(description)
{
 script_id(12029);
 script_version ("$Revision: 1.12 $");
 name["english"] = "MyDoom Virus Backdoor";

 script_name(english:name["english"]);
 
 desc["english"] = "
MyDoom backdoor is listening on this port. 
A cracker may connect to it to retrieve secret 
information, e.g. passwords or credit card numbers...

See also :  
http://securityresponse.symantec.com/avcenter/venc/data/w32.novarg.a@mm.html
http://securityresponse.symantec.com/avcenter/venc/data/w32.mydoom.f@mm.html

For a detailed description (to include partial decompilation):
http://www.math.org.il/newworm-digest1.txt

Solution: Use an Anti-Virus package to remove it.
Risk factor : Critical";


 script_description(english:desc["english"]);
 
 summary["english"] = "Detect MyDoom worm";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("os_fingerprint.nasl");
 exit(0);
}

include('global_settings.inc');

os = get_kb_item("Host/OS/icmp");
if ( os && "Windows" >!< os ) exit(0);


ports = make_list();
if ( thorough_tests )
{
 for ( port = 3127 ; port < 3198 ; port ++ ) 
 {
	ports = make_list(ports, port);
 }
}


ports = make_list(ports, 1080,80,3128,8080,10080);

foreach port (ports)
{
 if ( get_port_state(port) ) 
 {
	req = string("a");
	soc = open_sock_tcp(port);
	if ( soc ) 
	{
	send(socket:soc, data:req);
	r = recv(socket:soc, length:10, timeout:3);
	close(soc);
	if ( r && (strlen(r) == 8) && (ord(r[0]) == 4) ) security_hole(port); 
	}
 }
}

