#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15949);
 script_bugtraq_id(11889); 
 script_version("$Revision: 1.2 $");
 name["english"] = "phpDig Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running phpDig, an open-source search engine
written in PHP. 

The remote version of this software is vulnerable to a vulnerability
which may allow an attacker to temper with the integrity of the remote
host.

Solution : Upgrade to version 1.8.5 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of phpMyAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 req = http_get(port:port, item:dir + "/search.php");
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 # <title>PhpDig 1.8.4</title>
 if ( "<title>PhpDig" >< res )
 {
  if ( egrep(pattern:"<title>PhpDig (0\.|1\.([0-7]\.|8\.[0-4][^0-9]))", string:res) )
	{
	 security_hole(port);
	 exit(0);
	}
 }
}
