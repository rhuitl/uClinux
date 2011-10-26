#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20368);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0041");
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(11919, 11920);
 script_cve_id("CVE-2004-0899", "CVE-2004-0900");
 name["english"] = "Vulnerabilities in DHCP (885249) (network check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to DHCP service.

Description :

The remote host has the Windows DHCP server installed.

There is a flaw in the remote version of this server which may allow an
attacker to execute arbitrary code on the remote host with SYSTEM
privileges.

Solution : 

Microsoft has released a set of patches for Windows NT :

http://www.microsoft.com/technet/security/bulletin/ms04-042.mspx

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if MS04-042 is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("dcetest.nasl", "smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb");
 script_require_keys("Services/DCE/6bffd098-a112-3610-9833-46c3f874532d");
 exit(0);
}

include ('smb_func.inc');

os = get_kb_item ("Host/OS/smb") ;
if ( !os || "Windows 4.0" >!< os )
  exit(0);

# DHCPSERVER Service
port = get_kb_item ("Services/DCE/6bffd098-a112-3610-9833-46c3f874532d");
if (!port)
  exit (0);

if (!get_port_state (port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"6bffd098-a112-3610-9833-46c3f874532d", vers:1);
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


# DhcpGetVersion - opcode : 0x1C
#
# long  DhcpGetVersion (
#  [in][unique][string] wchar_t * arg_1,
#  [in] long arg_2,
#  [in, out] long * arg_3,
#  [in] long arg_4,
#  [out] struct_1 ** arg_5,
#  [out] long * arg_6,
#  [out] long * arg_7
# );


data = class_parameter (ref_id:0x20000, name:get_host_ip()) +
       raw_dword (d:0) +
       raw_dword (d:0) +
       raw_dword (d:0) ;


ret = dce_rpc_request (code:0x1C, data:data);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

close (soc);

resp = dce_rpc_parse_response (data:resp);
if (strlen(resp) != 12)
  exit (0);

val = get_dword (blob:resp, pos:strlen(resp)-4);
if (val != 0)
  exit (0);

major = get_dword (blob:resp, pos:0);
minor = get_dword (blob:resp, pos:4);

# patched version 4.1
# vulnerable 1.1

if (major < 4)
  security_hole (port);
