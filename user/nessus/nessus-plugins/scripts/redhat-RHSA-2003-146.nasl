#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12389);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0204");

 name["english"] = "RHSA-2003-146: arts";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  This erratum provides updated KDE packages to resolve a vulnerability in
  the handling of PostScript and PDF files.

  KDE is a graphical desktop environment for the X Window System.

  KDE versions up to and including KDE 3.1.1 have a vulnerability caused by
  neglecting to use the -dSAFER option when previewing in Konquerer. An
  attacker can prepare a malicious PostScript or PDF file which provides the
  attacker with access to the victim\'s account and privileges when the victim
  opens this malicious file for viewing, or when the victim browses a
  directory containing this malicious file with file previews enabled in the
  browser.

  This erratum provides packages containing KDE 2.2.2 with backported patches
  to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-146.html
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
if ( rpm_check( reference:"arts-2.2.2-7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-2.2.2-9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-2.2.2-9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-2.2.2-4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-2.2.2-4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-2.2.2-7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-2.2.2-7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-2.2.2-7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-devel-2.2.2-7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arts-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0204", value:TRUE);
}

set_kb_item(name:"RHSA-2003-146", value:TRUE);
