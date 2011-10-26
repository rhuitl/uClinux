#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12417);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0686");

 name["english"] = "RHSA-2003-262: pam_smb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated pam_smb packages are now available which fix a security
  vulnerability (buffer overflow).

  The pam_smb module is a pluggable authentication module (PAM) used to
  authenticate users using an external Server Message Block (SMB) server.

  A buffer overflow vulnerability has been found that affects unpatched
  versions of pam_smb up to and including 1.1.6.

  On systems that use pam_smb and are configured to authenticate a
  remotely accessible service, an attacker can exploit this bug and
  remotely execute arbitrary code. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2003-0686 to this issue.

  Red Hat Enterprise Linux contains a version of pam_smb that is vulnerable
  to this issue, however pam_smb is not enabled by default.

  Users of pam_smb are advised to upgrade to these erratum packages, which
  contain a patch to version 1.1.6 to correct this issue.

  Red Hat would like to thank Dave Airlie of the Samba team for notifying us
  of this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-262.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pam_smb packages";
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
if ( rpm_check( reference:"pam_smb-1.1.6-9.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"pam_smb-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0686", value:TRUE);
}

set_kb_item(name:"RHSA-2003-262", value:TRUE);
