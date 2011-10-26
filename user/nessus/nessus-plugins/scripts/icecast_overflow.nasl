#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10600);
 script_bugtraq_id(2264);
 script_cve_id("CVE-2001-0197");
 script_version ("$Revision: 1.10 $");
 
 name["english"] = "ICECast Format String";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server claims to be running ICECast 1.3.7 or 1.3.8beta2.

These versions are vulnerable to a format string attack which may
allow an attacker to execute arbitary commands on this host.


Solution : Upgrade to a newer version.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "icecast format string";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
  script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8000);
if(!port) exit(0);

banner = tolower(get_http_banner(port:port));
if ( ! banner ) exit(0);

if("icecast/" >< banner && egrep(pattern:"icecast/1\.3\.(7|8 *beta[012])", string:banner))
      security_hole(port);
