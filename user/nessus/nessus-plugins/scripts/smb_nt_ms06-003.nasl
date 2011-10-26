#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20390);
 script_cve_id("CVE-2006-0002");
 script_bugtraq_id(16197); 
 script_version("$Revision: 1.4 $");

 name["english"] = "Vulnerability in TNEF Decoding in Microsoft Outlook and Microsoft Exchange Could Allow Remote Code Executio (902412)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the email client or
the email server.

Description :

The remote host is running a version of outlook or exchange which is vulnerable
to a bug in the Transport Neutral Encapsulation Format (TNEF) MIME attachment
handling routine which may allow an attacker execute arbitrary code on the remote
host by sending a specially crafted email.

Solution : 

Microsoft has released a set of patches for Office 2000, 2002, XP, 2003,
Exchange 5.0, 5.5 and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms06-003.mspx

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of OutLook / Exchange";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


version = hotfix_check_outlook_version();
if (version)
{
 CommonFilesDir = hotfix_get_commonfilesdir();
 if (CommonFilesDir )
 {
  login	=  kb_smb_login();
  pass  	=  kb_smb_password();
  domain 	=  kb_smb_domain();
  port    =  kb_smb_transport();
  if (!get_port_state(port))exit(1);

  soc = open_sock_tcp(port);
  if(!soc)exit(1);

  session_init(socket:soc, hostname:kb_smb_name());
  r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
  if ( r != 1 ) exit(1);

  hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if ( isnull(hklm) )
  {
   NetUseDel();
   exit(1);
  }

  value = NULL;
  key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Microsoft\Office\" + version + "\Outlook\InstallRoot", mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
   value = RegQueryValue(handle:key_h, item:"Path");
   RegCloseKey(handle:key_h);
  }

  RegCloseKey(handle:hklm);
  NetUseDel();

  if (!isnull(value))
  {
   if (version == "9.0")
   {
    if ( hotfix_check_fversion(path:value[1], file:"Outex.dll", version:"8.30.3197.0") == HCF_OLDER ) security_warning(port);
   }
   else if (version == "10.0")
   {
    if ( hotfix_check_fversion(path:value[1], file:"Outllibr.dll", version:"10.0.6711.0") == HCF_OLDER ) security_warning(port);
   }
   else if (version == "11.0")
   {
    if ( hotfix_check_fversion(path:value[1], file:"Outllib.dll", version:"11.0.8002.0") == HCF_OLDER ) security_warning(port);
   }
  }
 }
}


version = get_kb_item ("SMB/Exchange/Version");
if ( !version ) exit (0);

if (version == 50)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 2) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"5.0.1462.22") == HCF_OLDER ) security_warning(port);

 hotfix_check_fversion_end();
}
else if (version == 55)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 4) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"5.5.2658.34") == HCF_OLDER ) security_warning(port);

 hotfix_check_fversion_end();
}
else if (version == 60)
{
 sp = get_kb_item ("SMB/Exchange/SP");
 rootfile = get_kb_item("SMB/Exchange/Path");
 if ( ! rootfile || ( sp && sp > 3) ) exit(0);
 rootfile = rootfile + "\bin";
 if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"6.0.6617.47") == HCF_OLDER ) security_warning(port);

 hotfix_check_fversion_end();
}

