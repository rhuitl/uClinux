#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13850);
 script_bugtraq_id(10819);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0557");
 
 name["english"] = "Fedora Core 1 2004-235: sox";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-235 (sox).

SoX (Sound eXchange) is a sound file format converter SoX can convert
between many different digitized sound formats and perform simple
sound manipulation functions, including sound effects.

Update Information:

Updated sox packages that fix buffer overflows in the WAV file handling
code are now available.

Buffer overflows existed in the parsing of WAV file header fields. It
was possible that a malicious WAV file could have caused arbitrary code to
be executed when the file was played or converted.  


Solution : http://www.fedoranews.org/updates/FEDORA-2004-235.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sox package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"sox-12.17.4-4.fc1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sox-devel-12.17.4-4.fc1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sox-debuginfo-12.17.4-4.fc1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"sox-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0557", value:TRUE);
}
