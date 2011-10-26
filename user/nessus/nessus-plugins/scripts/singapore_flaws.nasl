#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15987);
 script_cve_id("CVE-2004-1407", "CVE-2004-1408", "CVE-2004-1409");
 script_bugtraq_id(11990);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "Singapore Gallery Multiple Flaws";
 script_name(english:name["english"]);
 
 desc["english"] = "
Singapore is a PHP based photo gallery web application.

The remote version of this software is vulnerable to multiple vulnerabilities
which may allow an attacke read arbitrary files on the remote host or to
execute arbitrary PHP commands.

Solution: Upgrade to Singapore 0.9.11 or newer.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "The presence of Singapore Gallery";
 
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

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = http_get(item:dir + "/index.php", port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);

 if(egrep(pattern:"Powered by.*singapore\..*singapore v0\.([0-8]\.|9\.([0-9][^0-9]|10))", string:buf) )
	{
 	security_hole(port);
	exit(0);
	}
}
