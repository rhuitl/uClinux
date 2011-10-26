#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22529);
 script_version("$Revision: 1.2 $");
 script_cve_id("CVE-2006-3436");

 name["english"] = "Vulnerabilities in ASP.NET could allow information disclosure (922770)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote .Net Framework is vulnerable to a cross site scripting attack.

Description :

The remote host is running a version of the ASP.NET framework which contains
contains a cross site scripting vulnerability which could allow an attacker
to execute arbitrary code in the browser of the users visiting the remote
web site.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-056.mspx

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of the ASP.Net DLLs";

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
rootfile = hotfix_get_systemroot();
if(!rootfile) exit(0);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
dll =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft.Net\Framework\v2.0.50727\Aspnet_wp.exe", string:rootfile);


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


handle =  CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING); 
	
if( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
       if ((v[0] == 2 && v[1] == 0 && v[2] < 50727 ) ||
      	   (v[0] == 2 && v[1] == 0 && v[2] == 50727 && v[3] < 210 ) ) security_warning(port);
 }
}

NetUseDel();
