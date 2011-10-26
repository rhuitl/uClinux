#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16180);
 script_bugtraq_id(12284); 
 script_version("$Revision: 1.3 $");
 name["english"] = "SiteMinder HTML Page Injection Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Netegrity SiteMinder, an access management solution.

The remote version of this software is vulnerable to a page injection flaw
which may allow an attacker to trick users into sending him their username
and passwords, by sending them a link to the 'smpwservicescgi.exe' program
with a rogue TARGET argument value which will redirect them to an arbitrary
website after they authenticated to the remote service.

Solution : Upgrade to the newest version of this software
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for a flaw in SiteMinder";
 
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

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
req = http_get(port:port, item:dir + "/pwcgi/smpwservicescgi.exe?TARGET=http://www.nessus.org");
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
if ( '<input type=hidden name=TARGET value="http://www.nessus.org">' >< res &&
     '<form NAME="PWChange" METHOD="POST" ACTION="/siteminderagent/pwcgi/smpwservicescgi.exe">' >< res )
 {
	 security_warning(port);
	 exit(0);
 }
}
