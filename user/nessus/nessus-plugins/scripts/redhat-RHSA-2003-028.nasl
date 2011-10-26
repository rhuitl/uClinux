#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12356);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2002-1160");

 name["english"] = "RHSA-2003-028: pam";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated PAM packages are now available. These packages correct a bug in
  pam_xauth\'s handling of authorization data for the root user.

  [Updated 12 March 2003]
  Added packages for Red Hat Enterprise Linux ES and Red Hat Enterprise
  Linux WS

  The pam_xauth module is used to forward xauth information from user to user
  in applications such as the su command.

  Andreas Beck discovered that pam_xauth will forward authorization
  information from the root account to unprivileged users. This could be
  used by a local attacker to gain access to an administrator\'s X session.
  To exploit this vulnerability the attacker would have to get the
  administrator, as root, to use su to access the account belonging to the
  attacker.

  Users of pam_xauth are advised to upgrade to these errata packages which
  contain a patch which adds ACL (access control list) functionality to
  pam_xauth and disallows root forwarding by default.

  Thanks to Andreas Beck for reporting this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-028.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pam packages";
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
if ( rpm_check( reference:"pam-0.75-46.7.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam-devel-0.75-46.7.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"pam-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1160", value:TRUE);
}

set_kb_item(name:"RHSA-2003-028", value:TRUE);
