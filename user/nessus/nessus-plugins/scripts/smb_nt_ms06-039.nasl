#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22033);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(18915, 18913);
 script_cve_id("CVE-2006-0033", "CVE-2006-0007");
 
 name["english"] = "Vulnerabilities in Microsoft Office Filters Could Allow Remote Code Execution (915384)";
 

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the Microsoft
Office filters.

Description :

The remote host is running a version of some Microsoft Office
filters which are subject to various flaws which may allow arbitrary 
code to be run.

An attacker may use these to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user 
of the remote computer and have it import it with Microsoft Office.

Solution : 

Microsoft has released a set of patches for Office 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-039.mspx

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of some MS filters";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);

office_version = hotfix_check_office_version ();
if ( !office_version ) exit(0);

rootfile = hotfix_get_commonfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);

dll1  =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Shared\Grphflt\Gifimp32.flt", string:rootfile);
dll2 =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Shared\Grphflt\Gifimp32.flt_1033", string:rootfile);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if(!soc)exit(1);


session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);


handle =  CreateFile (file:dll2, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( isnull(handle) )
 handle =  CreateFile (file:dll1, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( !isnull(v) ) 
  {
	# v < 2003.1100.8020.0 => vulnerable
  	 if ( ( v[0] == 2003 &&  v[1] == 1100 && v[2] < 8020)  ||
	      ( v[0] == 2003 &&  v[1] < 1100 ) ||
	      ( v[0] < 2003 ) )  security_warning(port);
  }
}

NetUseDel();
