#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19407);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0029");
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2005-1984");
 script_bugtraq_id (14514);

 name["english"] = "Vulnerability in Printer Spooler Service Could Allow Remote Code Execution (896423) - Network Check";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to a flaw in the 
Spooler service.

Description :

The remote host contains a version of the Print Spooler service which
is vulnerable to a security flaw which may allow an attacker to execute
code on the remote host or crash the spooler service.

An attacker can execute code on the remote host with a NULL session against :
- Windows 2000

An attacker can crash the remote service with a NULL session against :
- Windows 2000
- Windows XP SP1

An attacker needs valid credentials to crash the service against :
- Windows 2003
- Windows XP SP2

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-043.mspx

Risk factor : 

 Critical / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);

 summary["english"] = "Determines the presence of update 896423 (network check)";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(139,445);
 exit(0);
}


include ('smb_func.inc');

function ReplyOpenPrinter ()
{
 local_var fid, data, rep, name;

 fid = bind_pipe (pipe:"\spoolss", uuid:"12345678-1234-abcd-ef00-0123456789ab", vers:1);
 if (isnull (fid))
   return 0;

 name = session_get_hostname();

 # only unicode is supported
 if (session_is_unicode ())
   name = class_name(name:name);
 else
 {
   session_set_unicode(unicode:1);
   name = class_name(name:name);
   session_set_unicode(unicode:0);
 }

 data = name + 
	raw_dword (d:0) +
	raw_dword (d:0) +
	raw_dword (d:0x201) +
	raw_dword (d:0x534E54) +
        raw_dword (d:0x201) +
        crap (data:"A", length:0x201);


 data = dce_rpc_pipe_request (fid:fid, code:0x3a, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 24))
   return 0;

 return 1;
}

os = get_kb_item ("Host/OS/smb") ;
if ( ! os || "Windows" >!< os || "Windows 4.0" >< os || "Windows 5.2" >< os ) exit(0);

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
 ret = ReplyOpenPrinter();
 if (ret == 1)
   security_hole (port:port);

 NetUseDel();
}
