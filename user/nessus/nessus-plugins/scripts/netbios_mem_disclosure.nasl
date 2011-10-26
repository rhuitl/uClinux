#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11830);
 script_version ("$Revision: 1.9 $");

 script_cve_id("CVE-2003-0661");
 script_bugtraq_id(8532);
 script_xref(name:"OSVDB", value:"2507");
 
 name["english"] = "NetBIOS Name Service Reply Information Leakage";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the NetBT name service which
suffers from a memory disclosure problem. 

An attacker may send a special packet to the remote NetBT name
service, and the reply will contain random arbitrary data from the
remote host memory.  This arbitrary data may be a fragment from the
web page the remote user is viewing, or something more serious like a
POP password or anything else. 

An attacker may use this flaw to continuously 'poll' the content of
the memory of the remote host and might be able to obtain sensitive
information. 


Solution : See http://www.microsoft.com/technet/security/bulletin/ms03-034.mspx
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Tests the NetBT NS mem disclosure";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencie("netbios_name_get.nasl");
 script_require_keys("SMB/NetBIOS/137");
 exit(0);
}

#
# The script code starts here
#

NETBIOS_LEN = 50;

sendata = raw_string(
rand()%255, rand()%255, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x20, 0x43, 0x4B,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x00, 0x00, 0x21, 0x00, 0x01
			);


if(!(get_udp_port_state(137))){
	exit(0);
	}
	
soc = open_sock_udp(137);
send(socket:soc, data:sendata, length:NETBIOS_LEN);

result = recv(socket:soc, length:4096);
if(strlen(result) > 58)
{
 pad = hexstr(substr(result, strlen(result) - 58, strlen(result)));
 close(soc);
 
 sleep(1);
 
 soc2 = open_sock_udp(137);
 if(!soc2)exit(0);
 send(socket:soc2, data:sendata, length:NETBIOS_LEN);
 result = recv(socket:soc2, length:4096);
 if(strlen(result) > 58)
 {
  pad2 = hexstr(substr(result, strlen(result) - 58, strlen(result)));
  if(pad != pad2)security_warning(port:137, proto:"udp");
 }
}
