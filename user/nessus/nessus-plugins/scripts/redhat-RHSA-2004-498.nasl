#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15428);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0815");

 name["english"] = "RHSA-2004-498: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated samba packages that fix an input validation vulnerability are now
  available.

  Samba provides file and printer sharing services to SMB/CIFS clients.

  Karol Wiesek discovered an input validation issue in Samba prior to 3.0.6.
  An authenticated user could send a carefully crafted request to the Samba
  server, which would allow access to files outside of the configured file
  share. Note: Such files would have to be readable by the account used
  for the connection. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0815 to this issue.

  This issue does not affect Red Hat Enterprise Linux 3 as a previous erratum
  updated to Samba 3.0.6 which is not vulnerable to this issue.

  Users of Samba should upgrade to these updated packages, which contain an
  upgrade to Samba-2.2.12, which is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-498.html
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
if ( rpm_check( reference:"samba-2.2.12-1.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.12-1.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.12-1.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.12-1.21as", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"samba-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0815", value:TRUE);
}

set_kb_item(name:"RHSA-2004-498", value:TRUE);
