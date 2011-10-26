#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15952);
 script_cve_id("CVE-2004-1396");
 script_bugtraq_id(11909);
 script_version("$Revision: 1.5 $");

 name["english"] = "Nullsoft Winamp Remote Denial of Service";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using WinAMP, a popular media player
which handles many files format (mp3, wavs and more...)

The remote version of this software is vulnerable to a denial of 
service vulnerability when it processes malformed .mp4 and .m4a
files.

An attacker may exploit this flaw by sending malformed files to a
victim on the remote host.

Solution : Upgrade to the newest version of WinAMP when available.
Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinAMP";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
 script_require_keys("SMB/Winamp/Version");
 exit(0);
}


version = get_kb_item("SMB/Winamp/Version");
if ( ! version ) exit(0);

if(version =~ "^([0-4]\.|5\.0\.[0-7]\.)")
  security_note(port);
