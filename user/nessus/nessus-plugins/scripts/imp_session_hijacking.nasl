#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10801);
 script_bugtraq_id(3525);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2001-0857");
 

 
 name["english"] = "IMP Session Hijacking Bug";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running IMP < 2.2.7

There is a security issue in all releases
prior to version 2.2.7

These versions are vulnerable to a cross-site 
scripting attack which can be used by
an attacker to hijack a victim's IMP session.


*** Nessus solely relied on the version number of your
*** installation, so if you applied the hotfix already,
*** consider this alert as a false positive

Solution: Upgrade to IMP 2.2.7
Risk factor : High";





 script_description(english:desc["english"]);
 
 summary["english"] = "Checks IMP version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dir[0] = "/";
dir[1] = "/imp/";
dir[2] = "/horde/imp/";

for(i=0;dir[i];i=i+1)
{
base = http_get(item:string(dir[i], "status.php3"), port:port);
soc = http_open_socket(port);
if(soc)
{
 send(socket:soc, data:base);
 code = recv_line(socket:soc, length:4096);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 302 .*", string:code))
 {
 r = http_recv(socket:soc);
 http_close_socket(soc);
 location = egrep(pattern:"^Location:", string:r);
 newloc = ereg_replace(pattern:"^Location: http://[^/]*(/.*)$",
		       string:location,
		       replace:"\1");
 soc = http_open_socket(port);
 req = http_get(item:newloc, port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 r = strstr(r, "IMP, Version");
 if(r)
  {
 r2 = strstr(r, "</font>");
 version = r - r2;
 if(ereg(pattern:"IMP, Version ([0-1]\..*)|(2\.([0-1]\..*|2\.[0-6][^0-9]))",
 	 string:version))security_hole(port);
   }
   exit(0);
   }
  }
  else exit(0);
 }
