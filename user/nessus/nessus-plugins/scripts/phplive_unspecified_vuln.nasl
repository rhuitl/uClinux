#
# This script is (C) Tenable Network Security
#
if(description)
{
 script_id(15928);
 script_version("$Revision: 1.3 $");
 script_cve_id("CVE-2004-2485");
 script_bugtraq_id(11863);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"12147");
 }

 script_name(english:"PHP Live! Remote Configuration File Include");
 desc["english"] = "
The remote host is running PHP Live! a live support system for web sites.

The remote version of this software contains an unspecifiedflaw which 
may allow an attacker to include a configuration file hosted on a third 
party server.

An attacker may exploit this flaw to execute arbitrary PHP code on the remote
host.

See also : http://archives.neohapsis.com/archives/apps/freshmeat/2004-11/0022.html
Solution : Upgrade to PHP Live! 2.8.2
Risk factor : High";
 
 script_description(english:desc["english"]);
 script_summary(english:"Checks for a flaw in PHP Live! < 2.8.2");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);



foreach dir ( make_list( "/phplive", cgi_dirs() ) )
{
 req = http_get(item:dir + "/index.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( ! res  ) exit(0);
 if ( egrep(pattern:"Powered by .*PHP.*Live!", string:res ) )
 {
  if ( egrep(pattern:"v([0-1]\.|2\.[0-7]|2\.8\.[0-2][^0-9]).*&copy; OSI Codes Inc.", string:res ) )
	security_hole ( port );
 }
 
}
