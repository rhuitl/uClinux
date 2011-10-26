#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(22494);
 script_cve_id("CVE-2006-5156");
 script_bugtraq_id(20288);
 script_xref(name:"OSVDB", value:"29421");
 
 script_version("$Revision: 1.3 $");

 name["english"] = "McAfee ePolicy Orchestrator HTTP Server Remote Buffer Overflow Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to a flaw in the
web service.

Description :

The remote host is running McAfee ePolicy Orchestrator web service.

The remote version of this software is vulnerable to a Stack Overflow
vulnerability. 

An unauthenticated attacker can exploit this flaw by sending a
specialy crafted packet to the remote host.  A successful exploitation
of this vulnerability would result in remote code execution with the
privileges of the SYSTEM. 

See also :

http://www.remote-exploit.org/advisories/mcafee-epo.pdf

Solution : 

Install ePO 3.5.0 Path 6.

Risk factor : 

Critical / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of ePO";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(0);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password(); 
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);

if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(1);
}


key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Network Associates\ePolicy Orchestrator", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

item = RegQueryValue(handle:key_h, item:"InstallFolder");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);
if ( isnull(item) ) {
 NetUseDel();
 exit(0);
}

rootfile = item[1];
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:rootfile) + "\NaiMServ.Exe";

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(version) )
 {
  if ( (version[0] < 4) ||
       (version[0] == 3 && version[1] <= 5) ||
       (version[0] == 3 && version[1] == 5 && version[2] == 0 && version[3] <  715) )
 	security_hole(port);
 }
}
NetUseDel();
