#
# written by Renaud Deraison
#
# Ref:
# From: "Gregory Le Bras | Security Corporation" <gregory.lebras@security-corporation.com>
# To: <vulnwatch@vulnwatch.org>
# Date: Tue, 15 Apr 2003 13:28:32 +0200 
# Subject: [VulnWatch] [SCSA-016] Multiple vulnerabilities in Ez publish
#
#

if (description)
{
 script_id(11538);
 script_bugtraq_id(7347, 7349);
 script_version ("$Revision: 1.7 $");

 script_name(english:"ezPublish config disclosure");
 desc["english"] = "
ezPublish (a content management system) is installed on the remote host.

An attacker may retrieve the file 'settings/site.ini' and gather
interesting information about the remote host, as it contains the
configuration of ezPublish.

Solution : Prevent the download of .ini files from your web server
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if ezPublish config file can be retrieved");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


dir = make_list(cgi_dirs());
		


foreach d (dir)
{
 url = string(d, "/settings/site.ini");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if( "ConnectRetries" >< buf &&
     "UseBuiltinEncoding" >< buf)
   {
    security_warning(port:port);
    exit(0);
   }
}

