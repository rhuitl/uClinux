#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#------------------------------------------------------------
#  Modified by HD Moore <hdmoore@digitaldefense.net>
#        The original plugin actually took down the server,
#        this checks for the .htr ISAPI mapping but doesnt
#        actually try to overflow the server.

if(description)
{
 script_id(10116);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-a-0007");
 script_bugtraq_id(307);
 script_version ("$Revision: 1.35 $");
 script_cve_id("CVE-1999-0874");
 name["english"] = "IIS buffer overflow";
 name["francais"] = "Dépassement de buffer dans IIS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It might be possible to make the remote IIS server execute
arbitrary code by sending it a too long url ending in .htr.


Solution : see http://www.microsoft.com/technet/security/bulletin/ms99-019.mspx
Risk factor : High";

 

 script_description(english:desc["english"]);
 
 summary["english"] = "IIS buffer overflow";
 summary["francais"] = "Dépassement de buffer dans IIS";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison / Modifications by HD Moore <hdmoore@digitaldefense.net>",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison / HD Moore <hdmoore@digitaldefense.net>");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "www_too_long_url.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");

 script_exclude_keys("www/too_long_url_crash");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

banner = get_kb_item("www/hmap/" + port + "/description");
if (! banner) banner = get_http_banner(port:port);
if ( "IIS" >!< banner ) exit(0);

if(get_port_state(port))
{
 
 if( safe_checks() )
 {
  if(http_is_dead(port:port))exit(0);
  data = http_get(item:"/nessus.htr", port:port);
  soc  = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:data);
   b = recv_line(socket:soc, length:1024);
   http_close_socket(soc);
   if(!strlen(b))security_hole(port);
  }
  exit(0);
 }
 
 
 if(http_is_dead(port:port))exit(0);
 data1 = http_get(item:string(crap(4096), ".html"), port:port);
 data2 = http_get(item:string(crap(4096), ".htr"), port:port);
 soc = http_open_socket(port);
 if(soc)
 { 
  send(socket:soc, data:data1);
  b = recv_line(socket:soc, length:4096);
  http_close_socket(soc);
 
  if(!strlen(b))exit(0);

  soc = http_open_socket(port);
  if(!soc)exit(0);
  send(socket:soc, data:data2);
  b = recv_line(socket:soc, length:4096);
  http_close_socket(soc);
  if(!strlen(b))security_hole(port);
  
 }
}
