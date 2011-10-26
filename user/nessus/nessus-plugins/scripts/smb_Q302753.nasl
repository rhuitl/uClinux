#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17212);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(12641);
 name["english"] = "OFF2000: Office Programs Can Browse Restricted Drives (Q302753)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Microsoft Office which contains
a security flaw which may allow a user to browse restricted drivers.

An attacker may exploit this flaw to gain access to files he would otherwise
not have access to.

Solution : http://support.microsoft.com/?id=302753
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of MSO9.dll";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");



rootfile = hotfix_get_programfilesdir();
if(!rootfile) exit(1);

version = hotfix_check_office_version();
if ( !version || (version >< "9.0") )
  if ( ! hotfix_check_works_installed() ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
dll =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Office\Office\mso9.dll", string:rootfile);


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

handle = CreateFile (file:dll,  desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);


if( ! isnull(handle)  )
{
 v = GetFileVersion( handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
  if ( v[0] == 9 && v[1] == 0 && v[2] == 0 && v[3] < 4625 )
	 security_warning(port);
 }
 else 
 {
  NetUseDel();
  exit(1);
 }
}

NetUseDel();
