#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12419);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0690", "CVE-2003-0692");

 name["english"] = "RHSA-2003-270: kdebase";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated KDE packages that resolve a local security issue with KDM PAM
  support and weak session cookie generation are now available.

  KDE is a graphical desktop environment for the X Window System.

  KDE between versions 2.2.0 and 3.1.3 inclusive contain a bug in the KDE
  Display Manager (KDM) when checking the result of a pam_setcred() call.
  If an error condition is triggered by the installed PAM modules, KDM might
  grant local root access to any user with valid login credentials.

  It has been reported that one way to trigger this bug is by having a
  certain configuration of the MIT pam_krb5 module that leaves a session
  alive and gives root access to a regular user. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2003-0690
  to this issue.

  In addition, the session cookie generation algorithm used by KDM was
  considered too weak to supply a full 128 bits of entropy. This could make
  it possible for non-authorized users, who are able to bypass any host
  restrictions, to brute-force the session cookie and gain access to the
  current session. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2003-0692 to this issue.

  Users of KDE are advised to upgrade to these erratum packages, which
  contain security patches correcting these issues.

  Red Hat would like to thank the KDE team for notifying us of this issue and
  providing the security patches.




Solution : http://rhn.redhat.com/errata/RHSA-2003-270.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdebase packages";
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
if ( rpm_check( reference:"kdebase-2.2.2-11", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-2.2.2-11", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdebase-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0690", value:TRUE);
 set_kb_item(name:"CVE-2003-0692", value:TRUE);
}

set_kb_item(name:"RHSA-2003-270", value:TRUE);
