#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11693);
 script_version ("$Revision: 1.5 $");
 
 
 name["english"] = "PFTP clear-text passwords";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is running PFTP.

This software stores the list of user names and passwords 
in clear text in \Program Files\PFTP\PFTPUSERS3.USR.

An attacker with a full access to this host may use this flaw
to gain access to other FTP servers used by the same users.

Solution : None
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks PFTPUSERS3.USR";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_require_ports(139, 445);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
db =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\PFTP\PFTPUSERS3.USR", string:rootfile);



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

handle = CreateFile (file:db, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 security_warning(port);
 CloseFile(handle:handle);
}

NetUseDel();


