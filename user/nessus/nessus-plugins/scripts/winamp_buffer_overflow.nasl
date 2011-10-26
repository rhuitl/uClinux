#
# (C) Tenable Network Security
#
# Ref:
#  Date: Sat, 4 Jan 2003 05:00:47 -0800
#  From: D4rkGr3y <grey_1999@mail.ru>
#  To: bugtraq@securityfocus.com, submissions@packetstormsecurity.com,
#        vulnwatch@vulnwatch.org
#  Subject: [VulnWatch] WinAmp v.3.0: buffer overflow


if(description)
{
 script_id(11530);
 script_bugtraq_id(6515);
 script_version("$Revision: 1.4 $");

 name["english"] = "WinAMP3 buffer overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using WinAMP3, a popular media player
which handles many files format (mp3, wavs and more...)

This version has a buffer overflow which may allow an attacker
to execute arbitrary code on this host, with the rights of the user
running WinAMP.

To perform an attack, the attack would have to send a malformed
playlist (.b4s) to the user of this host who would then have to
load it by double clicking on it.

Since .b4s are XML-based files, most antivirus programs will let
them in.

Solution : Uninstall this software or upgrade to a version newer than 3.0 build 488
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinAMP";

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
if ( ! rootfile ) exit(1);
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
winamp3 =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\WinAmp3\studio.exe", string:rootfile);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();


if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if( ! soc )exit(1);


session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);

handle = CreateFile (file:winamp3, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( !isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 if ( isnull(version) )
 {
  NetUseDel();
  exit(1);
 }

 if ( version[0] == 1 && version[1] == 0 && version[2] == 0 && version[3] <= 488 )
	security_hole(port);

 CloseFile(handle:handle);
}


NetUseDel();
