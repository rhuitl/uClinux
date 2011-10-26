#
# (C) Tenable Network Security
#

if(description)
{
 script_id(21696);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2006-2370", "CVE-2006-2371");

 name["english"] = "Vulnerability in Routing and Remote Access Could Allow Remote Code Execution (911280) - Network check";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to execute code on the remote host.

Description :

The remote version of Windows contains a version of RRAS (Routing
and Remote Access Service) which is vulnerable to several memory
corruption vulnerabilities.

An attacker may exploit these flaws to execute code on the remote
service.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-025.mspx

Risk factor :

Medium / CVSS Base Score : 4.1
(AV:R/AC:L/Au:R/C:P/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 911280 - network check";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nativelanman.nasl","smb_login.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(139,445);
 exit(0);
}


include ('smb_func.inc');

global_var rpipe;

function  RasRpcDeleteEntry ()
{
 local_var fid, data, rep, ret;

 fid = bind_pipe (pipe:"\SRVSVC", uuid:"20610036-fa22-11cf-9823-00a0c911e5df", vers:1);
 if (isnull (fid))
   return 0;

 data = class_name (name:string("tns",rand())) +
	class_name (name:string("tns",rand())) ;

 data = dce_rpc_pipe_request (fid:fid, code:0x05, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);

 if (!rep || (strlen(rep) != 4))
   return 0;

 ret = get_dword (blob:rep, pos:0);
 if (ret == 0x26d)
   return 1;

 # patched == 0x80070005 (check if admin) or access denied
 return 0;
}

os = get_kb_item ("Host/OS/smb") ;
if ("Windows" >!< os) exit(0);

name	= kb_smb_name();
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);

r = NetUseAdd(share:"IPC$");
if ( r == 1 )
{
 ret = RasRpcDeleteEntry ();
 if (ret == 1)
   security_warning(port:port);

 NetUseDel();
}
