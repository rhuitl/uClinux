#
# (C) Tenable Network Security
#


if (description)
{
 script_id(16063);
 script_version ("$Revision: 1.5 $");

 script_cve_id("CVE-2005-0264", "CVE-2005-0265");
 script_bugtraq_id(12114);
 script_xref(name:"OSVDB", value:"12677");
 script_xref(name:"OSVDB", value:"12678");

 script_name(english:"Owl Multiple Vulnerabilities");
 desc["english"] = "
The remote host is using owl intranet engine, an open-source file sharing 
utility written in php.

The remote version of this software is vulnerable to various flaws which
may allow an attacker to execute arbitrary SQL statements against the 
remote database or to perform a cross site scripting attack against third
party users by using the remote server.

Solution : Upgrade to Owl 0.74.0 or newer
Risk factor : Medium";


 script_description(english:desc["english"]);
 script_summary(english:"Determines owl is installed");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


foreach d ( cgi_dirs() )
{
 req = http_get(item:d + "/browse.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 line = egrep(pattern:"<TITLE>Owl Intranet Owl ", string:res);
 if ( line )
 {
  if ( ereg(pattern:".*Owl 0\.([0-6].*|7[0-3])</TITLE>", string:line) )
	{
	 security_warning ( port );
	 exit(0);
	}
 }
}
