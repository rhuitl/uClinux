#
# (C) Tenable Network Security
#

if(description)
{
  script_id(16183);
  script_cve_id("CVE-2005-0296");
  script_bugtraq_id(12285);
  script_version("$Revision: 1.4 $");
  
  script_name(english:"Novell GroupWise WebAccess Authentication Bypass");

 desc["english"] = "
The remote host is running Novell GroupWise WebAccess, a commercial
commercial groupware package.

The remote version of this software is vulnerable to an authentication
bypass vulnerability.

An attacker requesting :

	/servlet/webacc?error=webacc

may bypass the authentication mechanism and gain access to the groupware
console.

Solution : None at this time
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks GroupWare Auth Bypass");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);


buf = http_get(item:"/servlet/webacc?error=webacc", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if ( "<TITLE>Novell WebAccess ()</TITLE>" >< r &&
     "/servlet/webacc?User.context=" >< r )
	security_warning(port);
