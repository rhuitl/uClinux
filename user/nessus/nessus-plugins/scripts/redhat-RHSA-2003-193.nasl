#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12400);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0370");

 name["english"] = "RHSA-2003-193: arts";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated KDE packages that resolve a vulnerability in KDE\'s SSL
  implementation are now available.

  KDE is a graphical desktop environment for the X Window System.

  KDE versions 2.2.2 and earlier have a vulnerability in their SSL
  implementation that makes it possible for users of Konqueror and other SSL
  enabled KDE software to fall victim to a man-in-the-middle attack.

  Users of KDE should upgrade to these erratum packages, which contain KDE
  2.2.2 with a backported patch to correct this vulnerability.




Solution : http://rhn.redhat.com/errata/RHSA-2003-193.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the arts packages";
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
if ( rpm_check( reference:"arts-2.2.2-8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-2.2.2-8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-2.2.2-8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-2.2.2-8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-devel-2.2.2-8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arts-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0370", value:TRUE);
}

set_kb_item(name:"RHSA-2003-193", value:TRUE);
