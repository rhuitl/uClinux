#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# based on php3_path_disclosure by Matt Moore
#
#
# See the Nessus Scripts License for details
#
# References
# From: "Peter_Grundl" <pgrundl@kpmg.dk>
# To: "bugtraq" <bugtraq@securityfocus.com>
# Subject: KPMG-2002006: Lotus Domino Physical Path Revealed
# Date: Tue, 2 Apr 2002 16:18:06 +0200
#

if(description)
{
 script_id(11009);
 script_bugtraq_id(4049);
 script_cve_id("CVE-2002-0245");
 script_version ("$Revision: 1.13 $");
 name["english"] = "Lotus Domino Banner Information Disclosure Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to obtain the physical path to the remote web root
by requesting a non-existent .pl file.

Solution : Upgrade to Dominor 5.0.10 if you're using it, or contact
your vendor for a patch
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Lotus Physical Path Disclosure Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Actual check starts here...

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 file = string("/cgi-bin/com5.pl");
 req = http_get(item:file, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 50[0-9] .*", string:r))
 {
 if(egrep(pattern:"[^A-Z][A-Z]:.*com5\.pl", string:r, icase:TRUE))
   	security_warning(port);
 }
}
