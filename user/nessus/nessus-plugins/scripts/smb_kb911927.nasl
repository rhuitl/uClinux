#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20928);
 script_bugtraq_id(16636);
 script_cve_id("CVE-2006-0013");
 script_version("$Revision: 1.4 $");
 name["english"] = "Vulnerability in Web Client Service Could Allow Remote Code Execution (911927) - network check";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote version of Windows contains a flaw in the Web Client service which 
may allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need credentials to log into the 
remote host.

Solution : 

Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-008.mspx

Risk factor : 

Medium / CVSS Base Score : 4.1
(AV:R/AC:L/Au:R/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 911927 - network check";

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

function  DavCreateConnection ()
{
 local_var fid, data, rep, ret;

 fid = bind_pipe (pipe:"\DAV RPC SERVICE", uuid:"c8cb7687-e6d3-11d2-a958-00c04f682e16", vers:1);
 if (isnull (fid))
   return 0;

 data = class_parameter (ref_id:0x20000, name:"c:") +
	class_name (name:"\\") +
	raw_dword (d:0) +
	class_parameter (ref_id:0x20008, name:crap(data:"A", length:0x101)) +
	class_parameter (ref_id:0x2000c, name:"tns") ;

 data = dce_rpc_pipe_request (fid:fid, code:0x00, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);

 if (!rep || (strlen(rep) != 4))
   return 0;

 ret = get_dword (blob:rep, pos:0);
 if (ret == 0x43)
   return 1;

 # patched == 0x57 (or access denied)
 return 0;
}

os = get_kb_item ("Host/OS/smb") ;
if ("Windows" >!< os) exit(0);

name	= kb_smb_name();
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r == 1 )
{
 ret = DavCreateConnection ();
 if (ret == 1)
   security_warning(port:port);

 NetUseDel();
}
