#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18488);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0020");
 script_bugtraq_id(13952);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2005-0563");
 name["english"] = "Vulnerability in Exchange Server 5.5 Outlook Web Access XSS (895179)";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote Web Server contains a script which is vulnerable to cross site
scripting attacks.

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

Microsoft has released a patch for OWA for Exchange 5.5 :

http://www.microsoft.com/technet/security/bulletin/ms05-029.mspx

Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms05-029 via the registry";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
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

if (version == 55)
{
 if (!get_kb_item ("SMB/Exchange/OWA"))
   exit (0);

 if (is_accessible_share())
 {
  rootfile = get_kb_item("SMB/Exchange/Path");
  if ( ! rootfile ) exit(1);

  rootfile = rootfile + "\bin";
  if ( hotfix_check_fversion(path:rootfile, file:"cdo.dll", version:"5.5.2658.34") == HCF_OLDER ) security_note(port);

  hotfix_check_fversion_end();
 }
 else if ( hotfix_missing(name:"895179") > 0 ) 
	security_note(get_kb_item("SMB/transport"));
}
