#
# (C) Tenable Network Security
#
if(description)
{
 script_id(12208);
 script_bugtraq_id(9105, 9107, 9658);
 script_cve_id("CVE-2004-0380");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0009");
 
 script_version("$Revision: 1.15 $");

 name["english"] = "Cumulative Update for Outlook Express (837009)";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote host has a version of Outlook express which has a bug in its
MHTML URL processor, which may allow an attacker to execute arbitrary
code on this host.

To exploit this flaw, an attacker would need to send a malformed email to
a user of this host using Outlook, or would need to lure him into visiting
a rogue website.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-013.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ms04-013";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl", "smb_nt_ms04-018.nasl", "smb_nt_ms05-030.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

port = get_kb_item("SMB/transport");
if(!port) port = 139;

if ( hotfix_check_sp(win2k:5,xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"823353") <= 0 ) exit(0);
if ( get_kb_item("SMB/897715") ) exit(0);

patch = get_kb_item ("SMB/KB823353");
if ( patch == TRUE ) exit (0);


version = get_kb_item ("SMB/OutlookExpress/MSOE.dll/Version");
if (!version)
  exit (0);

port = get_kb_item("SMB/transport");
if(!port) port = 139;

v = split (version, sep:".", keep:FALSE);

if ( v[0] == 5 )
	{
	 if ( (v[0] == 5 && v[1] < 50) || 
	      (v[0] == 5 && v[1] == 50 && v[2] < 4922) ||
	      (v[0] == 5 && v[1] == 50 && v[2] == 4922 && v[3] < 1500 ) ) { security_hole(port); }
	}
else if ( v[0] == 6 )
	{
	 if ( ( v[0] == 6 && v[1] == 0 && v[2] < 2720) ||
	      ( v[0] == 6 && v[1] == 0 && v[2] == 2720 && v[3] < 3000 ) ) { security_hole(port); }

	 else if ( ( v[0] == 6 && v[1] == 0 && v[2] > 2720 && v[2] < 2800) ||
	           ( v[0] == 6 && v[1] == 0 && v[2] == 2800 && v[3] < 1409 ) ) { security_hole(port); }

	 else if( ( v[0] == 6 && v[1] == 0 && v[2] > 2800 && v[2] < 3790 ) ||
	          ( v[0] == 6 && v[1] == 0 && v[2] == 3790 && v[3] < 137 ) ) { security_hole(port); }
	}

