#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19664);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2491");
 
 name["english"] = "Fedora Core 4 2005-803: pcre";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-803 (pcre).

Perl-compatible regular expression library. PCRE has its own native
API, but a set of 'wrapper' functions that are based on the POSIX API
are also supplied in the library libpcreposix. Note that this just
provides a POSIX calling interface to PCRE; the regular expressions
themselves still follow Perl syntax and semantics. The header file for
the POSIX-style functions is called pcreposix.h.

Update Information:

the new package includes a fix for a heap buffer overflow.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pcre package";
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
if ( rpm_check( reference:"pcre-5.0-4.1.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-devel-5.0-4.1.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"pcre-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2491", value:TRUE);
}
