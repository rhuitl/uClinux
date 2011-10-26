#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:045
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19924);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:045: mozilla,MozillaFirefox,epiphany,galeon";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:045 (mozilla,MozillaFirefox,epiphany,galeon).


Various security vulnerabilities in the mozilla browser suite and
the Mozilla Firefox browser have been reported and fixed upstream.

The Mozilla suite browser  has been updated to a security fix level
of Mozilla 1.7.11, the Mozilla Firefox browser has been updated to
a fix level of Firefox 1.0.6.


Security relevant bugs that are fixed include (but are not limited to):

MFSA 2005-56 Code execution through shared function objects
MFSA 2005-55 XHTML node spoofing
MFSA 2005-54 Javascript prompt origin spoofing
MFSA 2005-52 Same origin violation: frame calling top.focus()
MFSA 2005-51 The return of frame-injection spoofing
MFSA 2005-50 Possibly exploitable crash in InstallVersion.compareTo()
MFSA 2005-49 Stealing of sensitive information via _search and the Firefox sidebar
MFSA 2005-48 Same-origin violation with InstallTrigger callback
MFSA 2005-47 'Set as wallpaper' javascript: privilege escalation
MFSA 2005-46 XBL scripts ran even when Javascript disabled
MFSA 2005-45 Content-generated event vulnerabilities


This update also upgrades the version of the Mozilla suite for the
following products:

* SUSE Linux Desktop 1.0:
The original Mozilla 1.4 branch browser is upgraded to the Mozilla
1.7 branch version.

We were not able to port the galeon web browser included in SUSE
Linux Desktop 1.0 to support Mozilla 1.7 in time, so we no longer
support it.

The galeon package on SUSE Linux Desktop 1.0 is removed by this update.

* SUSE Linux Enterprise Server 8:
The original Mozilla 1.4 branch browser is upgraded to the Mozilla
1.7 branch version.

* SUSE Linux Enterprise Server 9:
The Mozilla version 1.6 shipped with GA of the SUSE Linux Enterprise
Server 9 was replaced by the Mozilla 1.7 branch version in Service
Pack 2.

* SUSE Linux 8.2, 9.0, 9.1:
The Mozilla version 1.4 and 1.6 contained in the SUSE Linux versions
8.2 up to 9.1 was replaced by the Mozilla 1.7 branch version.

We were not able to port the galeon and the epiphany web browsers
included in SUSE Linux 9.0 up to 9.1 to support Mozilla 1.7 in time,
so we will no longer support it.

The galeon and epiphany packages on SUSE Linux 9.0 and 9.1 are removed
by this update.


Solution : http://www.suse.de/security/advisories/2005_45_mozilla.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mozilla,MozillaFirefox,epiphany,galeon package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mozilla-1.7.8-19", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.8-19", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.8-19", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.8-19", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.8-19", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.8-19", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-cs-1.4-158", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-deat-1.4.1-11", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-hu-1.4-159", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirebird-1.0.6-2", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.8-20", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.8-20", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-cs-1.7.5-7", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-deat-1.7.6-4", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.8-20", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.8-20", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-hu-1.78-4", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.8-20", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.8-20", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.8-20", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.8-20", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.6-4.2", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.6-4.2", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.8-5.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.8-5.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-cs-1.7.5-4.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-deat-1.7.6-0.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.8-5.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.8-5.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-hu-1.78-0.5", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.8-5.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-ja-1.7.7-0.5", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-ko-1.75-0.5", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.8-5.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.8-5.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.8-5.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.6-4.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.6-4.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-1.2.10-0.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-extensions-0.8.2-4.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"epiphany-extensions-devel-0.8.2-4.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"galeon-1.3.19-6.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.2-17.12", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.2-17.12", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.2-17.12", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.2-17.12", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.2-17.12", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.2-17.12", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.2-17.12", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.2-17.12", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.0.6-4.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.0.6-4.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.5-17.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-calendar-1.7.5-17.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.5-17.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.5-17.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.7.5-17.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.5-17.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-spellchecker-1.7.5-17.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.7.5-17.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
