#
# (C) Tenable Network Security
#
#
# Ref:
#  From: "Matthew Murphy" <mattmurphy@kc.rr.com>
#  To: "BugTraq" <bugtraq@securityfocus.com>, 
#  Subject: Mod_gzip Debug Mode Vulnerabilities
#  Date: Sun, 1 Jun 2003 15:10:13 -0500


 desc["english"] = "
Synopsis :

The remote web server is prone to a format string attack.

Description :

The remote host is running mod_gzip with debug symbols compiled in. 
The debug code includes vulnerabilities that can be exploited by an
attacker to gain a shell on this host. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2003-06/0003.html

Solution : 

If you do not use this module, disable it completely, or
recompile it without the debug symbols.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(11686);

 script_cve_id("CVE-2003-0843");
 script_xref(name:"OSVDB", value:"10508");
 
 script_version("$Revision: 1.8 $");
 name["english"] = "mod_gzip format string attack";
 script_name(english:name["english"]);

 script_description(english:desc["english"]);

 summary["english"] = "mod_gzip detection";

 script_summary(english:summary["english"]);

 script_category(ACT_MIXED_ATTACK);


 script_copyright(english:"This script is Copyright (C) 2003-2006 Tenable Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");



 
port = get_http_port(default:80);


if(!get_port_state(port))exit(0);



req = http_get(item:"/index.html", port:port);
tmp = egrep(pattern:"^User-Agent", string:req);
if(tmp) req -= tmp;
idx = stridx(req, string("\r\n\r\n"));
req = insstr(req, '\r\nAccept-Encoding: gzip, deflate\r\n\r', idx , idx);
res = http_keepalive_send_recv(port:port, data:req);


if("Content-Encoding: gzip" >< res)
{
 if(safe_checks())
 {
  # Avoid FP...
  if("Apache" >!< res || "mod_gzip" >!< res)exit(0);
  
  report = string(
    desc["english"],
    "\n\n",
    "Plugin output :\n",
    "\n",
    "Note that Nessus could not verify whether mod_gzip has the debug\n",
    "symbols enabled because safe checks were enabled. As a result,\n",
    "this may be a false-positive.\n"
  );
  security_hole(port:port, data:report);
  exit(0);
 }
 
 
req = http_get(item:"/nessus.html?nn", port:port);
req -= egrep(pattern:"^User-Agent", string:req);
idx = stridx(req, string("\r\n\r\n"));
req = insstr(req, '\r\nAccept-Encoding: gzip, deflate\r\n\r', idx , idx);
soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:req);
res = http_recv(socket:soc);
close(soc);

if(strlen(res))
 {
 req = http_get(item:"/nessus.html?%n", port:port);
 req -= egrep(pattern:"^User-Agent", string:req);
 idx = stridx(req, string("\r\n\r\n"));
 req = insstr(req, '\r\nAccept-Encoding: gzip, deflate\r\n\r', idx , idx);
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 res = http_recv(socket:soc);
 if(!res)security_hole(port:port, data:desc["english"]);
 }
}
