#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# 

if(description)
{
 script_id(11616);
 script_bugtraq_id(7040);
 
 script_version("$Revision: 1.3 $");

 name["english"] = "DBTools DBManager Information Disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running DBManager, from DBTool - a GUI to
manager MySQL and Postgresql databases.

This program stores the passwords and IP addresses of 
the managed databases in an unencrypted file.

A local attacker could use this design error to
log into the managed databases and obtain their
data.

Solution : None at this time
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of DBManager.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(0);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\DBTools Software\DBManager Professional\DBManager.exe", string:rootfile);



name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();

if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if(!soc)exit(1);


session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);


handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 security_warning(port);
 CloseFile(handle:handle);
}

NetUseDel();
