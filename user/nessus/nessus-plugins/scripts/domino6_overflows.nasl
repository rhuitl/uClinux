#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#
# 
# This flaw is a pain to check for. We rely on the banner, and if that fails,
# we'll have to rely on the behavior of the remote server when it comes
# to 30x redirections.

if(description)
{
 script_id(11386);
 script_bugtraq_id(6870, 6871);
 script_version ("$Revision: 1.9 $");

 name["english"] = "Lotus Domino 6.0 vulnerabilities";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote Lotus Domino server, according to its version number,
is vulnerable to various buffer overflows and denial
of service attack.

An attacker may use these to disable this server or
execute arbitrary commands on the remote host.
	

Reference : http://www.nextgenss.com/advisories/lotus-hostlocbo.txt


Solution : Update to Domino 6.0.1
Risk factor : High";	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of the remote Domino Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "webmirror.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/domino");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Lotus Domino" >!< sig ) exit(0);

banner = get_http_banner(port:port);

if(egrep(pattern:"Lotus-Domino/(Release-)?[1-5]\..*", string:banner))
 {
  exit(0);
 }


if(egrep(pattern:"Lotus-Domino/6\.(0|0\.0)[^0-9]$", string:banner))
{
 security_hole(port);
 exit(0);
}

if(safe_checks()) exit(0);

#
# Next, we try a generic check, in case of the redirection
# is set for the start web page (happens often)


#
# Finally, we try the check for every 30x page that webmirror.nasl
# encountered
#

redirs = get_kb_list(string("www/", port, "/content/30x"));
if(isnull(redirs))redirs = make_list("/");
else redirs = make_list(redirs, "/");

foreach url (redirs)
{
 req = string("GET ", url, " HTTP/1.1\r\n","Host: foobar\r\n\r\n");
 res = http_keepalive_send_recv(port:port, data:req);

 if(egrep(pattern:"https?://foobar/.*", string:res)){
 	req = string("GET ", url, " HTTP/1.1\r\n", "Host: ", crap(400), "\r\n\r\n");
	res = http_keepalive_send_recv(port:port, data:req);
	if(!res)security_hole(port);
	else {
	 if("Domino" >< res)
	 {
	  if(ereg(pattern:"^HTTP/1\.[01] 3", string:res))
	  {
	  security_hole(port);
	  exit(0);
	  }
	 }
	}
       }
}
