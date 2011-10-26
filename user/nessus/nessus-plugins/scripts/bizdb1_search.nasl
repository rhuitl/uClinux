  
#
# Locate /cgi-bin/bizdb1-search.cgi
#
#
# This plugin was written in NASL by RWT roelof@sensepost.com 26/4/2000
# Regards,
# Roelof@sensepost.com


if(description)
{
 script_id(10383);
 script_bugtraq_id(1104);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0287");


 name["english"] = "bizdb1-search.cgi located";
 script_name(english:name["english"]);
 desc["english"] = "
BizDB is a web database integration product
using Perl CGI scripts. One of the scripts,
bizdb-search.cgi, passes a variable's
contents to an unchecked open() call and
can therefore be made to execute commands
at the privilege level of the webserver.

The variable is dbname, and if passed a
semicolon followed by shell commands they
will be executed. This cannot be exploited
from a browser, as the software checks for
a referrer field in the HTTP request. A
valid referrer field can however be created
and sent programmatically or via a network
utility like netcat.

see also : http://www.hack.co.za/daem0n/cgi/cgi/bizdb.htm

Risk factor : High";


 script_description(english:desc["english"]);
 summary["english"] = "Determines the presence of cgi-bin/bizdb1-search.cgi";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000 Roelof Temmingh <roelof@sensepost.com>");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

cgi = string("bizdb1-search.cgi");
res = is_cgi_installed_ka(item:cgi, port:port);
if( res ) {
	if ( is_cgi_installed_ka(item:"nessus" + rand() + ".cgi", port:port) ) exit(0);
	security_hole(port);
}
