#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15817);
 script_cve_id("CVE-2004-1119");
 script_bugtraq_id(11730);
 script_version("$Revision: 1.8 $");

 name["english"] = "Nullsoft Winamp IN_CDDA.dll Remote Buffer Overflow Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using WinAMP5, a popular media player
which handles many files format (mp3, wavs and more...)

This version has a buffer overflow which may allow an attacker
to execute arbitrary code on this host, with the rights of the user
running WinAMP.

To perform an attack, the attack would have to send a malformed
playlist (.m3u) to the user of this host who would then have to
load it by double clicking on it.

Solution : Uninstall this software or upgrade to version 5.07.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinAMP";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_hotfixes.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");




rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Winamp\winamp.exe", string:rootfile);


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

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 ver = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ver )
 {
  version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
  set_kb_item(name:"SMB/Winamp/Version", value:version);
 }

 if(egrep(pattern:"^5\.0\.[0-6]", string:version))
  security_hole(port);
}

NetUseDel();
