#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18574);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2003-0427");
 
 name["english"] = "Fedora Core 4 2005-405: mikmod";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-405 (mikmod).

MikMod is one of the best and most well known MOD music file players
for UNIX-like systems.  This particular distribution is intended to
compile fairly painlessly in a Linux environment. MikMod uses the OSS
/dev/dsp driver including all recent kernels for output, and will also
write .wav files. Supported file formats include MOD, STM, S3M, MTM,
XM, ULT, and IT.  The player uses ncurses for console output and
supports transparent loading from gzip/pkzip/zoo archives and the
loading/saving of playlists.

Install the mikmod package if you need a MOD music file player.


* Mon Jun  6 2005 Martin Stransky <stransky redhat com> 3.1.6-35.FC4

- fixed #159290,#159291 - CVE-2003-0427
- fixed playing mod files from tar archive



Solution : http://www.redhat.com/archives/fedora-announce-list/2005-June/msg00014.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mikmod package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mikmod-3.1.6-35.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mikmod-devel-3.1.6-35.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mikmod-debuginfo-3.1.6-35.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mikmod-", release:"FC4") )
{
 set_kb_item(name:"CVE-2003-0427", value:TRUE);
}
