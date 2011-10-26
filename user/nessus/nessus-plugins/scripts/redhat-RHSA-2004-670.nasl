#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15992);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1154");

 name["english"] = "RHSA-2004-670: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated samba packages that fix an integer overflow vulnerability are now
  available for Red Hat Enterprise Linux 3.

  Samba provides file and printer sharing services to SMB/CIFS clients.

  Greg MacManus of iDEFENSE Labs has discovered an integer overflow bug in
  Samba versions prior to 3.0.10. An authenticated remote user could exploit
  this bug which may lead to arbitrary code execution on the Samba server.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-1154 to this issue.

  Users of Samba should upgrade to these updated packages, which contain
  backported security patches, and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-670.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the samba packages";
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
if ( rpm_check( reference:"samba-3.0.9-1.3E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.9-1.3E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.9-1.3E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.9-1.3E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"samba-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1154", value:TRUE);
}

set_kb_item(name:"RHSA-2004-670", value:TRUE);
