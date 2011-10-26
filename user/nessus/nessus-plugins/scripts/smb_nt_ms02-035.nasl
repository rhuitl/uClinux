#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11322);
 script_bugtraq_id(5203);
 script_cve_id("CVE-2002-0643");
 script_version("$Revision: 1.13 $");

 name["english"] = "MS SQL Installation may leave passwords on system";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It may be possible to get SQL server administrator password.

Description :

The installation process of the remote MS SQL server left 
files named 'setup.iss' on the remote host.

These files contain the password assigned to the 'sa' account
of the remote database.

An attacker may use this flaw to gain full administrative
access to your database.

Solution :

Microsoft has released a set of patches for SQL Server 7 and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-035.mspx

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Reads %windir%\setup.iss";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");



rootfile = hotfix_get_systemroot();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
rootfile =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\setup.iss", string:rootfile);


port    = kb_smb_transport();
if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);


session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if ( r != 1 ) exit(1);

foreach file (make_list("MSSQL7\Install\setup.iss", rootfile))
{
 handle =  CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

 if ( ! isnull(handle) ) 
 {
  resp = ReadFile(handle:handle, length:16384, offset:0);
  CloseFile(handle:handle);
  if("svPassword=" >< resp){
	security_hole(port);
	NetUseDel();
	exit(0);
	}
 }
}

NetUseDel();
