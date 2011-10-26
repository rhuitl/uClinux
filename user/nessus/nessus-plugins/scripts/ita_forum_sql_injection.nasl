#
# (C) Tenable Network Security
#


if(description)
{
 script_id(16197);
 script_bugtraq_id(12290);
 script_version("$Revision: 1.2 $");
 name["english"] = "ITA Forum Multiple SQL Injection Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running ITA Forum, a forum software written in PHP.

There is a SQL injection issue in the remote version of this software which
may allow an attacker to execute arbitrary SQL statements on the remote host
and to potentially overwrite arbitrary files on the remote system, by
sending a malformed value to several files on the remote host.

Solution : Upgrade to the latest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection in ITA Forum";
 
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

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


function check(loc)
{
 res = http_keepalive_send_recv(port:port, data:http_get(item:loc + "/search.php?Submit=true&search=');", port:port));
 if ( res == NULL ) exit(0);
 if ( "mysql_fetch_array()" >< res &&
      "Powered by ITA Forum" >< res ) {
	 security_hole(port);
	 exit(0);
	}
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  check(loc:dir);
 }
