#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17637);
 script_bugtraq_id(12905);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0431", "CVE-2005-0903");
 
 name["english"] = "Quicktime PictureViewer Buffer Overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using QuickTime, a popular media player/Plug-in
which handles many Media files.

The remote version of this software contains a buffer overflow vulnerability
in its PictureViewer which may allow an attacker to execute arbitrary code
on the remote host.

To exploit this vulnerability, an attacker needs to send a malformed image
file to a victim on the remote host and wait for her to open it using
QuickTime PictureViewer

Solution : Upgrade to QuickTime version 6.5.2 or later.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of QuickTime Player/Plug-in";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("quicktime_installed.nasl");
 script_require_keys("SMB/QuickTime/Version");

 exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (ver && ver =~ "^([0-5]\.|6\.([0-4]\.|5\.[01]$))") security_hole(get_kb_item("SMB/transport"));
