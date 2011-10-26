#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18120);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1236");
  script_bugtraq_id(13285, 13288);

  name["english"] = "DUPortal/DUPortal Pro Multiple SQL Injection Vulnerabilities";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host is running DUPortal, a content management system
written in ASP.

The remote version of this software is vulnerable to several SQL
injection vulnerabiliies in files 'details.asp', 'search.asp',
'default.asp' ...

With a specially crafted URL, an attacker can exploit this flaw
to modify database queries, potentially even uncovering user
passwords for the application. 

Solution : None at this time.
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SQL injection vulnerability in DUPortal";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if ( ! port ) exit(0);

if(get_port_state(port))
{
   foreach dir (cgi_dirs())
   {
  	buf = http_get(item:dir + "/detail.asp?nChannel='1", port:port);
  	r1 = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);

  	buf = http_get(item:dir + "/home/search.asp?nChannel='1", port:port);
  	r2 = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);

  	if ( ( r == NULL ) || ( r2 == NULL ) ) exit(0);
  	if ( ( "Microsoft OLE DB Provider for ODBC Drivers error '80040e14'" >< r1 ) ||
             ( "Microsoft OLE DB Provider for ODBC Drivers error '80040e14'" >< r2 ) )
  	{
    		security_hole(port);
	 	exit(0);
  	}
   }
}
