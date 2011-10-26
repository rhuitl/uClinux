#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18438);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2003-0427");
 
 name["english"] = "Fedora Core 3 2005-404: mikmod";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-404 (mikmod).

MikMod is one of the best and most well known MOD music file players
for UNIX-like systems. This particular distribution is intended to
compile fairly painlessly in a Linux environment. MikMod uses the OSS
/dev/dsp driver including all recent kernels for output, and will also
write .wav files. Supported file formats include MOD, STM, S3M, MTM,
XM, ULT, and IT. The player uses ncurses for console output and
supports transparent loading from gzip/pkzip/zoo archives and the
loading/saving of playlists.

Install the mikmod package if you need a MOD music file player.


* Mon Jun 06 2005 Martin Stransky 3.1.6-31.FC3

- fixed #159290,#159291 - CVE-2003-0427
- fixed playing mod files from tar archive



Solution : http://www.fedoranews.org/blog/index.php?p=715
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
if ( rpm_check( reference:"mikmod-3.1.6-31.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mikmod-devel-3.1.6-31.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mikmod-debuginfo-3.1.6-31.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mikmod-", release:"FC3") )
{
 set_kb_item(name:"CVE-2003-0427", value:TRUE);
}
