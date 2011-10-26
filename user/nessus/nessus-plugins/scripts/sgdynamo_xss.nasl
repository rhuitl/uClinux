#
# This script written by Scott Shebby (12/2003) 
#
# See the Nessus Scripts License for details
#
#
# changes by rd:
#
# - Description
# - Support for multiple HTTP directories
# - HTTP Keepalive support


if(description)
{
 script_id(11955);
 script_bugtraq_id(4720);
 script_cve_id("CVE-2002-0375");
 script_version ("$Revision: 1.7 $");
 name["english"] = "sgdynamo_xss";
 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running the CGI 'sgdynamo.exe'. 

There is a bug in some versions of this CGI which makes it vulnerable to
a cross site scripting attack.

Solution : None at this time
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "sgdynamo.exe XSS Vulnerability";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Scott Shebby");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
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
 url = dir + "/sgdynamo.exe?HTNAME=<script>foo</script>";
 req = http_get(item:url, port:port);
 resp = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( resp == NULL ) exit(0);
 if ( "<script>foo</script>" >< res )
 {
   security_warning(port);
   exit(0);
 }
}
