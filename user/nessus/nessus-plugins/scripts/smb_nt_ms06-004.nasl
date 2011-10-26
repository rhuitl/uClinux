#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20904);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(16516);
 script_cve_id("CVE-2006-0020");

 name["english"] = "Cumulative Security Update for Internet Explorer (910620)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote host is missing the IE cumulative security update 910620.

The remote version of IE is vulnerable to several flaws which may allow an 
attacker to execute arbitrary code on the remote host.

Solution : 

Microsoft has released a set of patches for Windows 2000 :

http://www.microsoft.com/technet/security/bulletin/ms06-004.mspx

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 910620";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl","smb_nt_ms05-054.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


version = hotfix_check_ie_version ();
if (!version || !egrep (pattern:"^6\.", string:version)) exit (0);

if ( hotfix_check_sp(win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"5.0.3837.1200", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
if ( hotfix_missing(name:"910620") > 0 &&
     hotfix_missing(name:"916281") > 0 &&
     hotfix_missing(name:"918899") > 0 &&
     hotfix_missing(name:"912812") > 0 )
	{
	 minorversion = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion");
	if ( ( "910620" >!< minorversion ) &&
             ( "916281" >!< minorversion ) &&
             ( "918899" >!< minorversion ) &&
             ( "912812" >!< minorversion ) )
           security_warning(get_kb_item("SMB/transport"));
	}

}
