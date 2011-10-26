#
# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11725);
 script_bugtraq_id(267);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-1999-1030");
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"9826");

 name["english"] = "counter.exe vulnerability";
 name["francais"] = "Counter.exe vulnerability";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "
The CGI 'counter.exe' exists on this webserver.
Some versions of this file are vulnerable to remote exploit.
An attacker may make use of this file to gain access to
confidential data or escalate their privileges on the Web
server.

Solution : remove it from the cgi-bin or scripts directory.

More info can be found at: http://www.securityfocus.com/bid/267

Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "Checks for the counter.exe file";

 script_summary(english:summary["english"]);

 script_category(ACT_MIXED_ATTACK); # mixed


 script_copyright(english:"This script is Copyright (C) 2003 John Lampe",
		francais:"Ce script est Copyright (C) 2003 John Lampe");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

directory = "";

foreach dir (cgi_dirs())
{
  if(is_cgi_installed_ka(item:string(dir, "/counter.exe"), port:port))
  {
    if (safe_checks() == 0)
    {
      req = string("GET ", dir, "/counter.exe?%0A", "\r\n\r\n");
      soc = open_sock_tcp(port);
      if (soc)
      {
        send (socket:soc, data:req);
        r = http_recv(socket:soc);
        close(soc);
      }
      else exit(0);

      soc2 = open_sock_tcp(port);
      if (!soc2) security_hole(port);
      send (socket:soc2, data:req);
      r = http_recv(socket:soc2);
      if (!r) security_hole(port);
      if (egrep (pattern:".*Access Violation.*", string:r) ) security_hole(port);
    }
	}
}
