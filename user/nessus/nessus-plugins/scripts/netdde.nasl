#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15572);

 script_cve_id("CVE-2004-0206");
 script_bugtraq_id(11372);
 script_xref(name:"IAVA", value:"2004-t-0035");
 script_xref(name:"OSVDB", value:"10689");

 script_version("$Revision: 1.8 $");
 name["english"] = "Vulnerability NetDDE Could Allow Code Execution (Netbios Check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote version of Windows is affected by a vulnerability in 
Network Dynamic Data Exchange (NetDDE).

An attacker may exploit this flaw to execute arbitrary code on the remote
host with the SYSTEM privileges.

Solution :

http://www.microsoft.com/technet/security/bulletin/MS04-031.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 841533 has been installed (Netbios)";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("netbios_name_get.nasl");
 script_require_ports(139);
 script_require_keys("SMB/name");
 exit(0);
}

include ('smb_nt.inc');

function ntol(buffer,begin)
{
 local_var len;

 len = 16777216*ord(buffer[begin+3]) +
       ord(buffer[begin+2])*65536 +
       ord(buffer[begin+1])*256 +
       ord(buffer[begin]);

 return len;
}


function raw_int32(i)
{
 local_var buf;

 buf = raw_string (
		 (i>>24) & 255,
	         (i>>16) & 255,
                 (i>>8) & 255,
                 (i) & 255
		 );
 return buf;
}


function raw_int(i)
{
 local_var buf;

 buf = raw_string (
		 (i) & 255,
                 (i>>8) & 255,
                 (i>>16) & 255,
                 (i>>24) & 255
		 );
 return buf;
}


function checksum(data)
{
 local_var len, chk, i, dlen;

 chk = 0xFFFFFFFF;
 dlen = strlen(data);
 len =  dlen -4;
 
 for (i=0;i<len;i+=4)
    chk += ntol(buffer:data, begin:i);

 while (i < dlen)
 {
  chk += ord(data[i]);
  i++;
 }

 return raw_int(i:chk);
}


function netbios(data)
{
 return  raw_int32(i:strlen(data)) + data;
}


function netdde(name,host)
{
 local_var lname,rhost,core,len;
 local_var name_hi,name_low,rhost_hi,rhost_low,core_hi,core_low;
 local_var main,header,data;

 lname = name + raw_string(0x01);
 rhost = host + raw_string(0x01);
 core = "CORE1.0" + raw_string(0x01);

 #lname length
 len = strlen(lname);
 name_hi = len / 256;
 name_low = len % 256;

 #rhost length
 len = strlen(rhost) + strlen(lname);
 rhost_hi = len / 256;
 rhost_low = len % 256;

 #core length
 len = strlen(core);
 core_hi = len / 256;
 core_low = len % 256;

 main = raw_string(0x01,0x00,0xBE,0x05,0x0A,0x00,0x00,name_hi,name_low,rhost_hi,rhost_low,core_hi,core_low,0x00) + lname + rhost + core + raw_string(0x2E);

 len = strlen(main);
 len_hi = len / 256;
 len_low = len % 256;

 header = raw_string(
 0x45,0x44,0x44,0x4E,0x00,0x00,0x00,
 len_hi,len_low,
 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
 len_hi,len_low,
 0x00,0x00,0x02,0x02,0x00,0x00,0x00,0x01,0x00,0x00,0x00) +
 #raw_string(0x82,0x8D,0xCB,0x3D);
 checksum(data:main);

 data = checksum(data:header) + header + main;
 
 data += raw_string(0x0d,0x12,0x0b,0x06,0x0d,0x18,0x1c,0x01,0x10,0x03,0x12,0x08,0x1d,0x1f,0x0a,0x0a,0x16,0x02,0x17,0x0e,0x1b,0x0d);

 data += crap(data:raw_string(0x03), length:0x19);

 data = netbios(data:data);

 return data;
}

hname = kb_smb_name();
if ( ! hname ) exit(0);

port = 139;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

 
session_request = raw_string(0x81, 0x00, 0x00, 0x44) + 
		  raw_string(0x20) +
		  netbios_encode(data:hname, service:0x1F) +
                  raw_string(0x00, 0x20) + 
		  "CACACACACACACACACACACACACACACABP" +
		  raw_string(0x00);

send(socket:soc, data:session_request);
r = smb_recv(socket:soc, length:4000);
if ( ! r ) exit(0);

if(ord(r[0])!=0x82)
 exit(0);

data = netdde(name:"NESSUS", host:hname);

send(socket:soc, data:data);
r = smb_recv(socket:soc, length:4000);

if (!r && (strlen(r) < 12))
  exit(0);

chk = substr(r,8,11);

if( "EDDN" >< chk)
{
 security_hole(port);
 exit(0);
}
