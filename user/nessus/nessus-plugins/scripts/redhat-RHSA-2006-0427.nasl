#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21366);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1931");

 name["english"] = "RHSA-2006-0427: irb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated ruby packages that fix a denial of service issue are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ruby is an interpreted scripting language for object-oriented programming.

  A bug was found in the way Ruby creates its xmlrpc and http servers. The
  servers use a non blocking socket, which enables a remote user to cause a
  denial of service condition if they are able to transmit a large volume of
  information from the network server. (CVE-2006-1931)

  Users of Ruby should update to these erratum packages, which contain a
  backported patch and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0427.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the irb packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"irb-1.8.1-7.EL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.1-7.EL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.1-7.EL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.8.1-7.EL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.8.1-7.EL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-mode-1.8.1-7.EL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.8.1-7.EL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"irb-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-1931", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0427", value:TRUE);
