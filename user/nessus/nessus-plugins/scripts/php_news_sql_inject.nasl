#
#  (C) Tenable Network Security
#  Ref: AccessX 
#

if(description)
{
 script_id(15861);
 script_cve_id("CVE-2004-2474");
 script_bugtraq_id(11748);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"12119");
 }
 script_version("$Revision: 1.5 $");
 
 name["english"] = "PHPNews sendtofriend.php SQL injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using PHPNews, an open source news application. 
It utilizes database to store the content.

A vulnerability exists in the remote version of this software
which may allow an attacker to inject arbitrary SQL code and 
possibly execute arbitrary code, due to improper validation of 
user supplied input in the 'mid' parameter of script 
'sendtofriend.php'.

Solution : Upgrade to the version 1.2.4 of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Makes a request to the remote host by supplying the mid paramter in the url";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security.");
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
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/phpnews/sendtofriend.php?mid='1'"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if ("mysql_fetch_assoc():" >< r  )
 {
   security_warning(port);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
