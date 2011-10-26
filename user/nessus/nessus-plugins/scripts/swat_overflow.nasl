#
# (C) Tenable Network Security
#

if(description)
{
 script_id(13660);
 script_bugtraq_id(10780);
 script_cve_id("CVE-2004-0600");
 script_version ("$Revision: 1.4 $");
 
 
 name["english"] = "SWAT overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running SWAT - a web-based administration tool for
Samba.

There is a buffer overflow condition in the remote version of this software
which might allow an attacker to execute arbitrary code on the remote host
by sending a malformed authorization request (or any malformed base64 data).

Solution : Upgrade to Samba 3.0.5
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "SWAT overflow";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK); # Or ACT_ATTACK ? Swat is started from inetd after all...
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);

 script_dependencie("swat_detect.nasl");
 script_require_ports("Services/swat", 901);
 exit(0);
}

#
# The script code starts here
#
include("http_keepalive.inc");
include("http_func.inc");

port = get_kb_item("Services/swat");
if(!port) port = 901;

if (get_port_state(port))
{
 req = string("GET / HTTP/1.0\r\nAuthorization: Basic aaa=\r\n\r\n");
 soc = http_open_socket(port);
 if ( ! soc ) exit(0);
 send(socket:soc, data:req);
 res = http_recv(socket:soc);
 close(soc);
 if ( ! res || 'realm="SWAT"' >!< res ) exit(0);

 req = string("GET / HTTP/1.0\r\nAuthorization: Basic =\r\n\r\n");
 soc = http_open_socket(port);
 if ( ! soc ) exit(0);
 send(socket:soc, data:req);
 res = http_recv(socket:soc);
 close(soc);
 if ( ! res ) security_hole(port);
} 
