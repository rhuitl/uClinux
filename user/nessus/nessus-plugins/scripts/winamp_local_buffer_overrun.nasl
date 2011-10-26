#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16199);
 script_bugtraq_id(10678);
 script_version("$Revision: 1.2 $");

 name["english"] = "Nullsoft Winamp Filename Handler Local Buffer Overrun";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using WinAMP, a popular media player
which handles many files format (mp3, wavs and more...)

The remote version of this software is vulnerable to a local buffer
overrun when handling a large file name. This buffer overflow may
be exploited to execute arbitrary code on the remote host.

An attacker may exploit this flaw by sending a file with an outrageously
long file name to a victim on the remote host. When the user will attempt
to open this file using WinAMP, a buffer overflow condition will occur.

Solution : Upgrade to WinAMP  5.0.4 or newer
Risk factor : High";


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

if(version =~ "^([0-4]\.|5\.0\.[0-3]\.)")
  security_hole(0);
