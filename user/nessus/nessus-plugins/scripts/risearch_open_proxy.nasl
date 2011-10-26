#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(14180);
 script_cve_id("CVE-2004-2061");
 script_bugtraq_id(10812);
 script_version("$Revision: 1.4 $");

 name["english"] = "RiSearch OpenProxy";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running RiSearch, a local search engine.

There is a flaw in the CGI 'show.pl' which is bundled with this 
software which may allow an attacker to use the remote host as an open
proxy by doing a request like :

http://www.example.com/cgi-bin/search/show.pl?url=http://www.google.com

An attacker may exploit this flaw to use the remote host as a proxy,
and therefore to connect anonymously to the internet.

Solution : Upgrade to the latest version of this software.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of RiSearch's search.pl";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}



include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(port:port, item:dir + "/search/show.pl?url=http://www.google.com");
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "<title>Google</title>" >< res &&
      "I'm Feeling Lucky" >< res ) 
	{
	 security_hole(port);
	 exit(0);
	}
}
