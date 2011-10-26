#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16317);
 script_bugtraq_id(12442);
 script_cve_id("CVE-2005-0085");
 
 script_version ("$Revision: 1.4 $");
 name["english"] = "ht://Dig htsearch.cgi XSS (2)";
 script_name(english:name["english"]);
 
 desc["english"] =  "
The remote host is running a version of ht://Dig which is vulnerable
to an unspecified cross site scripting attack.

With a specially crafted URL, an attacker may use the remote to
perform a cross site scripting attack against a user.

Solution : Upgrade to ht://Dig 3.2.0b7 or newer
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if ht://Dig is vulnerable to XSS flaw in htsearch.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
  script_dependencie("cross_site_scripting.nasl");
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
if ( ! port ) exit(0);

if(get_port_state(port))
{
   foreach dir (cgi_dirs())
   {
  	buf = http_get(item:dir + "/htsearch.cgi", port:port);
  	r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  	if( r == NULL )exit(0);
  	if( egrep(pattern:"ht://Dig ([0-2]\..*|3\.([01]\..*|2\.0(a|b[0-6][^0-9])))", string:r ) )
  	{
    		security_warning(port);
	 	exit(0);
  	}
   }
}
