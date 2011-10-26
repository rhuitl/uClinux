#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12394);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1308");

 name["english"] = "RHSA-2003-163: galeon";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Mozilla packages that fix various bugs and security issues in
  previous versions of Mozilla are now available.

  Mozilla is an open source Web browser.

  A heap-based buffer overflow in Netscape and Mozilla allows remote
  attackers to execute arbitrary code via a jar: URL that references a
  malformed .jar file, which overflows a buffer during decompression.

  These errata packages upgrade Mozilla to version 1.0.2, which is not
  vulnerable to this issue. Mozilla 1.0.2 also contains a number of other
  stability and security updates.




Solution : http://rhn.redhat.com/errata/RHSA-2003-163.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the galeon packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"galeon-1.2.11-0.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.0.2-4.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.0.2-4.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.0.2-4.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.0.2-4.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.0.2-4.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.0.2-4.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.0.2-4.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.0.2-4.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.0.2-4.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.0.2-4.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-psm-1.0.2-4.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"galeon-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1308", value:TRUE);
}

set_kb_item(name:"RHSA-2003-163", value:TRUE);
