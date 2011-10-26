#
# (C) Tenable Network Security
# 

desc["english"] = "
Synopsis :

The remote web server host the 'cvsweb' CGI

Description :

CVSweb is a web interface for a CVS repository. It allows
users to browse through the history of the source code of
a given project.

If you environement contains sensitive source code, the access
to this CGI should be password protected.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";



if(description)
{
 script_id(10402);
 script_version ("$Revision: 1.17 $");

 name["english"] = "CVSweb detection";
 script_name(english:name["english"]);
 script_description(english:desc["english"]);

 summary["english"] = "Determines whether cvsweb.cgi is installed on the remote host";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
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

port = get_http_port(default:80 );
if ( ! port ) exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(item:dir + '/cvsweb.cgi/', port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( ! res ) exit(0);

 generator = egrep(pattern:'<meta name="generator" content=', string:res);
 if ( ! generator ) exit(0);
 if ( "CVSweb" >< generator )
 {
   version = ereg_replace(pattern:'.*content="(.*)".*', string:generator, replace:"\1");
   report = desc["english"] + '\n\nPlugin output:\n\nCVSweb version : ' + version;
   set_kb_item(name:"www/" + port + "/cvsweb/version", value:version);
   security_note(port:port, data:report);
 }
}
