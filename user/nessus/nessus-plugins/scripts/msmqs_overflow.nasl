#
# (C) Tenable Network Security
#
# Windows XP SP1 can be identified remotely without harm, not Windows 2000

if(description)
{
 script_id(18027);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0011");
 script_version("$Revision: 1.6 $");
 script_bugtraq_id(13112);
 script_cve_id("CVE-2005-0059");

 script_version("$Revision: 1.6 $");
 name["english"] = "Vulnerability in MSMQ Could Allow Code Execution (Network Check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote version of Windows is affected by a vulnerability in 
Microsoft Message Queuing Service (MSMQ).

An attacker may exploit this flaw to execute arbitrary code on the remote
host with the SYSTEM privileges.

Solution :

http://www.microsoft.com/technet/security/bulletin/MS05-017.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 892944 has been installed (Network test)";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencies("smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(2103);
 exit(0);
}

include ('smb_func.inc');

 
function dce_rpc_parse_response2 (data)
{
 local_var resp, flag, len, alloc, tmp, dat;

 if (strlen (data) < 24)
   return NULL;
   
 flag = get_byte (blob:data, pos:3);
 len = get_word (blob:data, pos:8) - 24;
 alloc = get_dword (blob:data, pos:16);

 if (strlen (data) < (24 + len))
   return NULL;
   
 return substr (data, 24, 24 + len - 1);
}

os = get_kb_item("Host/OS/smb");
if ( "Windows 5.1" >!< os ) exit (0);

port = 2103;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

host_ip = get_host_ip();

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"fdb3a030-065f-11d1-bb9b-00a024ea5525", vers:1);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

if (!resp)
{
 close (soc);
 exit (0); 
}

ret = dce_rpc_parse_bind_ack (data:resp);
if (isnull (ret) || (ret != 0))
{
 close (soc);
 exit (0);
}


data = raw_string (
        0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x12, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 
        0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x54, 0x00, 0x43, 0x00, 
        0x50, 0x00, 0x3A, 0x00, 0x31, 0x00, 0x32, 0x00, 0x37, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x30, 0x00, 
        0x2E, 0x00, 0x31, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x30, 0x00, 0x33, 0x00, 0x5C, 0x00, 
        0x50, 0x00, 0x52, 0x00, 0x49, 0x00, 0x56, 0x00, 0x41, 0x00, 0x54, 0x00, 0x45, 0x00, 0x24, 0x00, 
        0x5C, 0x00, 0x6E, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x75, 0x00, 0x73, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x06, 0x01, 0x11, 0x1b, 0x1e, 
        0x0c, 0x09, 0x0d, 0x00, 0x08, 0x1b, 0x17, 0x05, 0x12, 0x07, 0x0f, 0x10, 0x0d, 0x1a, 0x11, 0x1a
);

ret = dce_rpc_request (code:0x02, data:data);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

close (soc);

resp = dce_rpc_parse_response2 (data:resp);
if (strlen(resp) != 36)
  exit (0);

# patched = 0xC00E0045
# not patched = 0xC00E0003

val = get_dword (blob:resp, pos:strlen(resp)-4);
if (val == 0xC00E0003)
  security_hole (port);
