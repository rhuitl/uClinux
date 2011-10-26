#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20049);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2337");

 name["english"] = "RHSA-2005-799: irb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ruby packages that fix an arbitrary command execution issue are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ruby is an interpreted scripting language for object-oriented programming.

  A bug was found in the way ruby handles eval statements. It is possible for
  a malicious script to call eval in such a way that can allow the bypass of
  certain safe-level restrictions. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2005-2337 to this issue.

  Users of Ruby should update to these erratum packages, which contain a
  backported patch and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-799.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the irb packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"irb-1.6.4-2.AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-1.6.4-2.AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.6.4-2.AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.6.4-2.AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.6.4-2.AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.6.4-2.AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"irb-1.8.1-7.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.1-7.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.1-7.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.8.1-7.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.8.1-7.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-mode-1.8.1-7.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.8.1-7.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"irb-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2337", value:TRUE);
}
if ( rpm_exists(rpm:"irb-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2337", value:TRUE);
}

set_kb_item(name:"RHSA-2005-799", value:TRUE);
