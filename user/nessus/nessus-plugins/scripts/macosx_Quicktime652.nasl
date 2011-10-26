#TRUSTED 769fb57ccd991d4b79ee4217c366abab2f622cb7c71f94b2dfa28c5cfa2486beb9008df91fa2319ca5e3bbb08bf5014b27a726a1fef8d3204828f089c4295654bab5e6ab1f82585b3a6b9062198681856dfed5ced479fa8ec85d156e1e89f1f9f7ca3f61ce268d0ecad04339c7e79efc159e6a4cfc1eb1d8d0142ecdacd2db59b5382758ce01e7e050916e03f84b2020608ef9587a795feba84f3aa36d453f41933055e171ea1fb843f58b7e6a2683b6f63e609887b42660eca0664d077225ed8d86244144cd95e911c34d3e6ff1ad320546821588d10d29cfe2ac66272f6ed25d4d3762d6d149d78e8482db05dd441027582e17e70c71461e94249afa89ab4801d3c4fe367cafd291cfb4b1bd7706cd9960f9dc106acd3c9dba2e63e8a7a4069a823b353c7614b0d44119f74d1a32d245dac72cd68c3470582e6a838f026efdb543a1d13dad06bbf59495db8c2785305350b5c48ca5b02393b6177c39ecdfff86a6227a51e32cb0d2b4f5f2efdf3120eb1d9628a03ad20b3eb989405c1071acf71bdffc70f3c598b5cc6dd8fd5ed41bddde95f36b33224f97332c05517f9f0b2c2aef4cde03073a03258c6ac6771e398b41def14cbea7141cc46a187c3320fec370c7dae9e09cc43ca1f38b7e5528261d6e9d4c6484b4898914f34fa2ce02fca9d47852a136b79bd129834b832b88d7bdcc0e5dbf69c9f0c2aba59784af956a
#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15573);
 script_version ("1.4");
 script_bugtraq_id(11553);
 script_cve_id("CVE-2004-0988");
 name["english"] = "Quicktime < 6.5.2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Mac OS X host is running a version of Quicktime which is older
than Quicktime 6.5.2.

There is an integer overflow vulnerability in the remote version of this
software which may allow an attacker to execute arbitrary code on the remote
host. To exploit this flaw, an attacker would need to send a malformed
media file to a victim on the remote host, or set up a rogue web site and
lure a user on the remote host into visiting it.

Solution : http://docs.info.apple.com/article.html?artnum=61798
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Quicktime 6.5.2";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

include("ssh_func.inc");

cmd = 'cd /System/Library/Quicktime && osascript -e \'tell application "Finder" to get {version} of alias "::QuickTimeMPEG.component"\' | awk \'{print $2}\'';

if ( islocalhost() )
 buf = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
else
{
 soc = ssh_login_or_reuse_connection();
 if ( ! soc ) exit(0);
 buf = ssh_cmd(socket:soc, cmd:cmd);
 ssh_close_connection();
}

if ( buf !~ "^[0-9]" ) exit(0);

buf = chomp(buf);

set_kb_item(name:"MacOSX/QuickTime/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if ( int(version[0]) < 6 ||
    ( int(version[0]) == 6 && int(version[1]) < 5 ) ||
    ( int(version[0]) == 6 && int(version[1]) == 5 && int(version[2]) < 2 ) ) security_hole ( 0 );
