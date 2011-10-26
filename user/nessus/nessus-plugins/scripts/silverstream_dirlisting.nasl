#
# This script was written by Tor Houghton, but I looked at "htdig" by 
# Renaud Deraison <deraison@cvs.nessus.org>
#
# modifications by rd:
#	- pattern read is different
#	- request /SilverStream not /SilverStream/Pages
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added links to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10846);
 script_version ("$Revision: 1.6 $");
 #script_cve_id("CVE-XXXX-YYYY");
 name["english"] = "SilverStream directory listing";
 script_name(english:name["english"]);
 
 desc["english"] = "
SilverStream directory listings are enabled.
An attacker may use this problem to gain more knowledge
on this server and possibly to get files you would want
to hide.

Risk factor : Medium

Reference : http://online.securityfocus.com/archive/101/144786

Solution : Reconfigure the server so that others
cannot view directory listings";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if SilverStream directory listings are disabled.";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Tor Houghton");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);


if(get_port_state(port)) {
     buf = string("/SilverStream");
     buf = http_get(item:buf, port:port);
     rep = http_keepalive_send_recv(port:port, data:buf);
     if ( ! rep ) exit(0);
     lookfor = "<html><head><title>.*SilverStream.*</title>";
      
      if((egrep(pattern:lookfor, string:rep)) && ("/Pages" >< rep))
         security_warning(port);
}

