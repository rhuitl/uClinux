#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16152);
 script_bugtraq_id(12245, 12381);
 script_cve_id("CVE-2004-1150");
 script_version("$Revision: 1.5 $");

 name["english"] = "Nullsoft Winamp Multiple Unspecified Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using WinAMP, a popular media player
which handles many files format (mp3, wavs and more...).

The remote version of this software is vulnerable to various unspecified
vulnerabilties which may allow an attacker to execute arbitrary code on the
remote host.

An attacker may exploit this flaw by sending malformed files to a
victim on the remote host.

Solution : Upgrade to WinAMP 5.0.8c or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of WinAMP";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
 script_require_keys("SMB/Winamp/Version");
 exit(0);
}


version = get_kb_item("SMB/Winamp/Version");
if ( ! version ) exit(0);

if(version =~ "^([0-4]\.|5\.0\.[0-8]\.)")
  security_note(port);
