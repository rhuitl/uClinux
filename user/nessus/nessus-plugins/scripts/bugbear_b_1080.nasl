#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11733);

 script_version ("$Revision: 1.1 $");
 name["english"] = "Bugbear.B worm";
 name["francais"] = "Ver Bugbear.B";

 script_name(english:name["english"], francais: name["francais"]);
 
 desc["english"] = "
BugBear.B backdoor is listening on this port. 
A cracker may connect to it to retrieve secret 
information, e.g. passwords or credit card numbers...

The BugBear.B worm includes a key logger and can kill 
antivirus or personal firewall softwares. It propagates 
itself through email and open Windows shares.

Solution: 
- Use an Anti-Virus package to remove it.
- Close your Windows shares
- See http://www.symantec.com/avcenter/venc/data/w32.bugbear.b@mm.removal.tool.html

Risk factor : Critical";


 script_description(english:desc["english"]);
 
 summary["english"] = "Detect Bugbear.B worm";
 summary["francais"] = "Détecte le ver Bugbear.B";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(
  english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(1080);
 script_dependencies("find_service.nes");
 exit(0);
}

#
include("misc_func.inc");


#
# bugbear.b is bound to port 1080. It sends data which seems to
# be host-specific when it receives the letter "p"
#
port = 1080;
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:"p");
r = recv(socket: soc, length: 308);
close(soc);
if(!strlen(r))exit(0);


soc = open_sock_tcp(port);
if (! soc) exit(0);
send(socket: soc, data: "x");
r2 = recv(socket: soc, length: 308);
if(strlen(r2)) { exit(0); }
close(soc);





if(strlen(r) > 10 )
{
 security_hole(port); 
 register_service(port: port, proto: "bugbear_b");
 exit(0); 
}
