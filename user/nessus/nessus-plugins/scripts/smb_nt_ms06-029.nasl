#
# (C) Tenable Network Security
#

if(description)
{
 script_id(21695);
 script_version("$Revision: 1.3 $");
 script_cve_id("CVE-2006-1193");
 script_bugtraq_id(18381);
 name["english"] = "Vulnerability in Microsoft Exchange Server Running Outlook Web Access Could Allow Script Injection (912442)";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote Web Server contains a script which is vulnerable to script injection
attacks.

Description :

The remote host is running a version of the Outlook Web Access which contains 
cross site scripting flaws.

This vulnerability could allow an attacker to convince a user 
to run a malicious script. If this malicious script is run, it would execute 
in the security context of the user. 
Attempts to exploit this vulnerability require user interaction. 

This vulnerability could allow an attacker access to any data on the 
Outlook Web Access server that was accessible to the individual user.

It may also be possible to exploit the vulnerability to manipulate Web browser caches
and intermediate proxy server caches, and put spoofed content in those caches.

Solution : 

Microsoft has released a patch for OWA for Exchange 2000/2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-029.mspx

Risk factor :

Low / CVSS Base Score : 1.8
(AV:R/AC:H/Au:NR/C:N/I:P/A:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms06-029 via the registry";

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

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");

# now check for the patch
if ( hotfix_check_nt_server() <= 0 ) 
	exit(0);

version = get_kb_item ("SMB/Exchange/Version");

if (!get_kb_item ("SMB/Exchange/OWA"))
  exit (0);


if (version == 60)
{
 if (is_accessible_share())
 {
  rootfile = get_kb_item("SMB/Exchange/Path");
  if ( ! rootfile ) exit(1);

  rootfile = rootfile + "\bin";
  if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"6.5.7233.69") == HCF_OLDER ) security_note(port);
  else if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"6.5.7650.28", min_version:"6.5.0.0") == HCF_OLDER ) security_note(port);

  hotfix_check_fversion_end();
 }
 else if ( hotfix_missing(name:"912442") > 0 ) 
	security_note(get_kb_item("SMB/transport"));
}
else if (version == 65)
{
 if (is_accessible_share())
 {
  rootfile = get_kb_item("SMB/Exchange/Path");
  if ( ! rootfile ) exit(1);

  rootfile = rootfile + "\bin";
  if ( hotfix_check_fversion(path:rootfile, file:"Mdbmsg.dll", version:"5.5.2658.34") == HCF_OLDER ) security_note(port);

  hotfix_check_fversion_end();
 }
 else if ( hotfix_missing(name:"912442") > 0 ) 
	security_note(get_kb_item("SMB/transport"));
}
