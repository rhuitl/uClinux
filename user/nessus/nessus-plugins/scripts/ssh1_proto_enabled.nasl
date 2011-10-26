#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10882);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(2344);
 script_cve_id("CVE-2001-0361");

 
 name["english"] = "SSH protocol version 1 enabled";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote service offers an insecure cryptographic protocol

Description :

The remote SSH daemon supports connections made
using the version 1.33 and/or 1.5 of the SSH protocol.

These protocols are not completely cryptographically
safe so they should not be used.

Solution : 

Disable compatiblity with version 1 of the protocol.
		
Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Negotiate SSH connections";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 - 2006 Tenable Network Security");

 family["english"] = "General";

 script_family(english:family["english"]);
 script_dependencie("ssh_proto_version.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}




function test_version(version)
{
soc = open_sock_tcp(port);
if( ! soc )exit(0);
str = string("SSH-", version, "-NessusSSH_1.0\n");
r = recv_line(socket:soc, length:255);
if ( ! r ) exit(0);
if(!ereg(pattern:"^SSH-.*", string:r))
 { 
 close(soc);
 return(0);
 }
send(socket:soc, data:str);
r = recv_line(socket:soc, length:255);
close(soc);
if(!r)return(0);
if(ereg(pattern:"^Protocol.*version", string:r))return(0);
else return(1);
}




port = get_kb_item("Services/ssh");
if(!port)port = 22;
if(!get_port_state(port) || ! get_kb_item("SSH/banner/" + port) )exit(0);

if(test_version(version:"9.9"))exit(0);


if((test_version(version:"1.33")) ||
   (test_version(version:"1.5")))
	 security_note(port);
	
