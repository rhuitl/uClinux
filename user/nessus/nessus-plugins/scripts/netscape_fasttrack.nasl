#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10156);
 script_version ("$Revision: 1.22 $");

 script_cve_id("CVE-1999-0239");
 script_bugtraq_id(481);
 script_xref(name:"OSVDB", value:"122");

 name["english"] = "Netscape FastTrack 'get'";
 script_name(english:name["english"]);
 
 desc["english"] = "When the remote web server is
issued a request with a lower-case 'get', it will return
a directory listing even if a default page such as index.html is 
present. 

Example :

		get / HTTP/1.0
		
Will return a listing of the root directory.

This allows an attacker to gain valuable information about the
directory structure of the remote host and could reveal the
presence of files which are not intended to be visible.

Solution : Upgrade your server to the latest version.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "'get / ' gives a directory listing";

 script_summary(english:summary["english"]); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/netscape-fasttrack");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

bad = "<title>index of /</title>";



function check(pattern, port)
{
 local_var req, res;
 
 
 req = http_get(item:"/", port:port);
 req = str_replace(string:req, find:pattern, replace:"get", count:1);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 res = tolower(res);
 if(bad >< res){
 	security_warning(port);
	exit(0);
  }
}


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

res = tolower(res);
if(bad >< res) exit(0);

# See www.securityfocus.com/bid/481/exploit

check(pattern:"GET", port:port);
check(pattern:"GET ", port:port);

