#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11808);
 script_bugtraq_id(8205);
 script_cve_id("CVE-2003-0352");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0011");
 script_version ("$Revision: 1.22 $");
 
 name["english"] = "Microsoft RPC Interface Buffer Overrun (823980)";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote version of Windows contains a flaw in the function 
RemoteActivation() in its RPC interface which may allow an attacker to 
execute arbitrary code on the remote host with the SYSTEM privileges.

A series of worms (Blaster) are known to exploit this vulnerability in the 
wild.

Solution :

http://www.microsoft.com/technet/security/bulletin/MS03-026.mspx 

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
 
 script_description(english:desc["english"]);
 
 summary["english"] = "[LSD] Critical security vulnerability in Microsoft Operating Systems";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencies("smb_nativelanman.nasl", "msrpc_dcom2.nasl");
 script_require_ports(139, 445); 
 exit(0);
}

include ('smb_func.inc');

if(get_kb_item("SMB/KB824146"))exit(0);
if(!get_kb_item("SMB/KB824146_launched"))exit(0);

function RemoteActivation ()
{
 local_var fid, data, rep, ret;

 fid = bind_pipe (pipe:"\epmapper", uuid:"4d9f4ab8-7d1c-11cf-861e-0020af6e7c57", vers:0);
 if (isnull (fid))
   return 0;

 data = # DCOM informations
	raw_word (w:5) +
        raw_word (w:6) +
        raw_dword (d:1) +
        raw_dword (d:0) +
        encode_uuid (uuid:"54454e41-424c-454e-4554-574f524b5345") +
	raw_dword (d:0) +

	# CLSID
	encode_uuid (uuid:"53454e5b-5553-5d53-5b4e-45535355535d") +

	# ObjectName
	class_parameter (ref_id:0x20004, name:"\\A"+raw_string(0)+"A\\AA") +

	# NULL pointer
	raw_dword (d:0) +

	# ClientImpLevel
	raw_dword (d:0) +
	# Modes
	raw_dword (d:0) +

	# interfaces (only 1)
	raw_dword (d:1) + 
	raw_dword (d:0x20008) +
	raw_dword (d:1) +
	encode_uuid (uuid:"00000000-0000-0000-0000-000000000000") +

	# rest of data
	raw_dword (d:0) +
	raw_dword (d:0);

 data = dce_rpc_pipe_request (fid:fid, code:0x00, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 68))
   return 0;

 ret = get_dword (blob:rep, pos:strlen(rep)-24);
 if ((ret == 0x80080004) || (ret == 0x80070005))
   return 0;

 return 1;
}

os = get_kb_item ("Host/OS/smb") ;
if (("Windows 5.1" >!< os) && ("Windows 5.0" >!< os) && ("Windows 5.2" >!< os) && ("Windows 4.0" >< os))
  exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 445;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

name	= kb_smb_name();

session_init(socket:soc, hostname:name);

r = NetUseAdd(share:"IPC$");
if ( r == 1 )
{
 ret = RemoteActivation();
 if (ret == 1)
   security_hole (port:port);

 NetUseDel();
}
