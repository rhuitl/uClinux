#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12361);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2002-0593", "CVE-2002-0594", "CVE-2002-1091", "CVE-2002-1126");

 name["english"] = "RHSA-2003-046: galeon";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Mozilla packages are now available for Red Hat Linux Advanced
  Server. These new packages fix vulnerabilities in previous versions of
  Mozilla.

  Mozilla is an open source Web browser. Versions of Mozilla prior to
  version 1.0.1 contain various security vulnerabilities. These
  vulnerabilities could be used by an attacker to read data off of the local
  hard drive, to gain information that should normally be kept private, and
  in some cases to execute arbitrary code. For more information on the
  specific vulnerabilities fixed please see the references below.

  All users of Mozilla should update to these errata packages containing
  Mozilla version 1.0.1 which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-046.html
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
if ( rpm_check( reference:"galeon-1.2.6-0.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.14.0-0.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.14.0-0.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-gnome-0.14.0-0.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.0.1-2.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.0.1-2.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.0.1-2.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.0.1-2.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.0.1-2.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.0.1-2.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.0.1-2.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.0.1-2.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.0.1-2.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.0.1-2.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-psm-1.0.1-2.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"galeon-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0593", value:TRUE);
 set_kb_item(name:"CVE-2002-0594", value:TRUE);
 set_kb_item(name:"CVE-2002-1091", value:TRUE);
 set_kb_item(name:"CVE-2002-1126", value:TRUE);
}

set_kb_item(name:"RHSA-2003-046", value:TRUE);
