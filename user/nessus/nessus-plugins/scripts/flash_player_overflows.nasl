#
#
# (C) Tenable Network Security
#
# Ref: http://www.macromedia.com/v1/handlers/index.cfm?ID=23821
#
# There's an old SWFlash.ocx which lies around when
# the new version is installed. Not sure what we should
# do with it.

if(description)
{
 script_id(11323);
 script_bugtraq_id(7005);
 script_version("$Revision: 1.14 $");

 name["english"] = "Security issues in the remote version of FlashPlayer";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote Windows host has a browser plugin that is prone to buffer
overflow attacks. 

Description :

The remote host has an old version of the Flash Player plugin
installed. 

An attacker may use this flaw to construct a malicious web site which
with a badly formed flash animation which will cause a buffer overflow
on this host, and allow him to execute arbitrary code with the
privileges of the user running Internet Explorer. 

See also : 

http://www.macromedia.com/v1/handlers/index.cfm?ID=23821

Solution : 

Upgrade to version 6.0.79.0 or newer.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of the remote flash plugin";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}



include("smb_func.inc");
include("smb_hotfixes.inc");


rootfile = hotfix_get_systemroot();
if(!rootfile) exit(1);
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:rootfile);



name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();

if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);


# per Josh Zlatin-Amishav, when Flash 8 is installed, the new installation 
# does not remove the old Flash.ocx file.


foreach f ( make_list("Flash9.ocx", "Flash8b.ocx", "Flash8a.ocx", "Flash8.ocx", "Flash.ocx", "SWFlash.ocx") )
{

handle = CreateFile (file:string(file, "\\System32\\Macromed\\Flash\\", f ),
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) ) break;
}

if( ! isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 CloseFile(handle:handle);

 if ( !isnull(version) )
 {
 v = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
 set_kb_item(name:"MacromediaFlash/version", value:v);
 if ( version[0] < 6 || (version[0] == 6 && version[1] == 0 && version[2] <= 78) ) security_warning(port);
 }
}

NetUseDel();
