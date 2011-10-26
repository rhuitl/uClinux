#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16191);
 script_cve_id("CVE-2005-0374");
 script_bugtraq_id(12248);
 script_version("$Revision: 1.4 $");

 name["english"] = "BiTBOARD IMG BBCode Tag JavaScript Injection Vulnerability";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.4 $");
 
 desc["english"] = "
The remote host is running BiTBOARD, a web based bulletin board written in PHP.

The remote version of this software is vulnerable to a Javascript Injection 
which may allow an attacker to steal the http cookies of the regular users
of the remote site to gain unauthorized access to their account.

Solution : Upgrade to BiTBOARD 2.6 or newer
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of BiTBOARD";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

function check(url)
{
 req = http_get(item:url +"/index.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "the BiTSHiFTERS SDC" >< res )
 {
  if ( egrep(pattern:"BiTBOARD v([0.1]\..*|2\.[0-5]) Bulletin Board by.*the BiTSHiFTERS SDC</a>", string:res) ) {
	security_warning(port);
	exit(0);
	}
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
