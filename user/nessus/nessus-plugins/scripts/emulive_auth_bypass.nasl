#
# (C) Tenable Network Security
#
if(description)
{
 script_id(14805);
 script_cve_id("CVE-2004-1695", "CVE-2004-1696");
 script_bugtraq_id(11226);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Emulive Server4 Authentication Bypass";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running EmuLive Server4, a web and media streaming
server.

There is a flaw in the administrative interface of the remote service
which may allow an attacker to bypass the authentication procedure
of the remote service by requesting the file /public/admin/index.htm
directy.

An attacker may exploit this flaw to gain administrative access over
the remote service.

Solution : Upgrade to the newest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Requests the admin page of the remote EmuLive Server4";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
		
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 81);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:81);
req = http_get(item:"/PUBLIC/ADMIN/INDEX.HTM", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res && "Emulive Server4" >< res &&  "<title>Server4 Administration Console</title>" >< res  ) security_hole(port);
