#
# Written by Astharot <astharot@zone-h.org>
# 
# Reference: http://www.zone-h.org/advisories/read/id=3864
#

if(description)
{
 script_id(12042);
 script_cve_id("CVE-2004-2175");
 script_bugtraq_id(9574, 12159);
 script_version("$Revision: 1.8 $");
 name["english"] = "SQL injection in ReviewPost PHP Pro"; 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host could be vulnerable to SQL Injection, because
you are probably running ReviewPost PHP Pro, a web-based software
that manage users opinions.

There is a flaw in this software which may allow a malicious
attacker to inject arbitrary SQL queries which allows it to
fetch data from the database.

Solution : Download the vendor supplied patch at
http://www.photopost.com/members/forum/showthread.php?s=&threadid=98098

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Astharot");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


function check(dir)
{
 req = http_get(item:dir + "/showproduct.php?product=1'", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 
 
 
if ("id,user,userid,cat,date,title,description,manu,keywords,bigimage,bigimage2,bigimage3,views,approved,rating" >< res ) {
	security_hole(port);
	exit(0);
	}

 req = http_get(item:dir + "/showcat.php?cat=1'", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 
 if ("id,catname FROM rp_categories" >< res ) {
	security_hole(port);
	exit(0);
	}
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach dir (cgi_dirs()) 
 {
  check(dir:dir);
 }
