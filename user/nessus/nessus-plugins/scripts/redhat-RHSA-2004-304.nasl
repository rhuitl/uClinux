#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14310);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2003-0388");

 name["english"] = "RHSA-2004-304: pam";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated pam packages that fix a security vulnerability are now available
  for Red Hat Enterprise Linux 2.1.

  PAM (Pluggable Authentication Modules) is a system security tool that
  allows system administrators to set an authentication policy without
  having to recompile programs that handle authentication.

  These updates fix a potential security problem present in the
  pam_wheel module. These updates correct a bug in the pam_lastlog
  module which prevented it from properly manipulating the /var/log/lastlog
  entry for users with very high user IDs.

  The pam_wheel module is used to restrict access to a particular service
  based on group membership. If the pam_wheel module was used with the
  "trust" option enabled, but without the "use_uid" option, any local
  user would be able to spoof the username returned by getlogin(). The user
  could therefore gain access to a superuser account without supplying a
  password. In Red Hat Enterprise Linux 2.1, pam_wheel is not used by
  default. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2003-0388 to this issue.

  When manipulating the entry in /var/log/lastlog, which corresponds to a
  given user, the pam_lastlog module calculates the location of the entry by
  multiplying the UID and the length of an entry in the file. On some
  systems, the result of this calculation would mistakenly be truncated to 32
  bits for users with sufficiently high UIDs.

  All users of pam should upgrade to these updated packages, which
  resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-304.html
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
if ( rpm_check( reference:"pam-0.75-46.9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pam-devel-0.75-46.9", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"pam-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0388", value:TRUE);
}

set_kb_item(name:"RHSA-2004-304", value:TRUE);
