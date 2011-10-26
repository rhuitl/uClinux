#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19390);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1992");

 name["english"] = "RHSA-2005-543: irb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ruby packages that fix an arbitrary command execution issue are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ruby is an interpreted scripting language for object-oriented programming.

  A bug was found in the way Ruby launched an XMLRPC server. If an XMLRPC
  server is launched in a certain way, it becomes possible for a remote
  attacker to execute arbitrary commands within the XMLRPC server. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-1992 to this issue.

  Users of Ruby should update to these erratum packages, which contain a
  backported patch and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-543.html
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
if ( rpm_check( reference:"irb-1.8.1-7.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.1-7.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.1-7.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.8.1-7.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.8.1-7.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-mode-1.8.1-7.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.8.1-7.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"irb-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1992", value:TRUE);
}

set_kb_item(name:"RHSA-2005-543", value:TRUE);
