#
# This script was written by Tenable Network Security
#

if(description)
{
 script_id(16276);
 script_bugtraq_id(12398); 
 script_version ("$Revision: 1.5 $");

 name["english"] = "phpPGAds HTTP Response Splitting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
There is a flaw in the remote phpPgAds/phpAdsNew, a banner management
and tracking system written in PHP.

This version of phpPgAds/phpAdsNew is vulnerable to an HTTP response
splitting vulnerability.
An attacker, exploiting this flaw, would be able to redirect users to
another site to perform another attack (steal their credentials).

Solution: Upgrade to phpPGAds/phpAdsNew 2.0.2

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of phpPGAds/phpAdsNew";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
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
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var req, r;
 req = http_get(item:string(loc, "admin/index.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if ( egrep(pattern:"<meta name='generator' content='(phpPgAds|phpAdsNew) ([0-1]\..*|2\.0|2\.0\.[0-1]) - http://www\.phpadsnew\.com'>", string:r))
 {
   security_warning(port);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

