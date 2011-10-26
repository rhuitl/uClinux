#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20107);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2977");

 name["english"] = "RHSA-2005-805: pam";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated pam package that fixes a security weakness is now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  PAM (Pluggable Authentication Modules) is a system security tool that
  allows system administrators to set an authentication policy without
  having to recompile programs that handle authentication.

  A bug was found in the way PAM\'s unix_chkpwd helper program validates user
  passwords when SELinux is enabled. Under normal circumstances, it is not
  possible for a local non-root user to verify the password of another local
  user with the unix_chkpwd command. A patch applied that adds SELinux
  functionality makes it possible for a local user to use brute force
  password guessing techniques against other local user accounts. The Common
  Vulnerabilities and Exposures project has assigned the name CVE-2005-2977
  to
  this issue.

  All users of pam should upgrade to this updated package, which contains
  backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-805.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pam packages";
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
if ( rpm_check( reference:"pam-0.77-66.13", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam-devel-0.77-66.13", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"pam-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2977", value:TRUE);
}

set_kb_item(name:"RHSA-2005-805", value:TRUE);
