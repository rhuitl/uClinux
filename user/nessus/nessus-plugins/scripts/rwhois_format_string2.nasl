#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10804);
script_cve_id("CVE-2001-0913");
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "rwhois format string attack (2)";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote rwhois daemon is vulnerable to a format string
attack when supplied malformed arguments to a malformed request.
(such as %p%p%p)

An attacker may use this flaw to gain a shell on this host.

*** Note that Nessus solely relied on the banner version to
*** issue this warning. If you manually patched rwhoisd, you
*** may not be vulnerable to this flaw

Risk factor : High
Solution : Disable this service or upgrade to version 1.5.7.3 or newer";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if rwhois is vulnerable to a format string attack";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/rwhois", 4321);
 exit(0);
}

#
# The script code starts here
#

port = 4321;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  # There's no way to determine remotely if the service if vulnerable
  # or not.
  r = recv(socket:soc, length:4096);
  if(egrep(pattern:"V-1\.([0-4]|5\.([0-6]|7\.[0-2]))", 
         string:r))security_hole(4321);
 }
}
