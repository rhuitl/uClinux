#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11052);
 script_bugtraq_id(5279);
 script_version("$Revision: 1.13 $");

 name["english"] = "BenHur Firewall active FTP firewall leak";
 script_name(english:name["english"]);

 desc["english"] = "
It is possible to connect on firewall-protected ports on the remote
host by setting one's source port to 20.

An attacker may use this flaw to access services that should not
be accessible to outsiders on this host.


Solution: Reconfigure your firewall to *not* accept anything
coming from port 20.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Connects to a few services with sport = 20";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2002 by Renaud Deraison");
 family["english"] = "Firewalls";
 script_family(english:family["english"]);
 exit(0);
}



include('global_settings.inc');

if(islocalhost() || NASL_LEVEL < 2204 )exit(0);


port = 8888;
	
soc = open_priv_sock_tcp(sport:20, dport:port);
if(soc){
	close(soc);
	soc = open_sock_tcp(port);
	if(soc){ close(soc); exit(0); }
	security_hole(port);
	}


