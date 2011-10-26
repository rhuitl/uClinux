#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18278);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0013");

 name["english"] = "RHSA-2005-371: ipxutils";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated ncpfs package is now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Ncpfs is a file system that understands the Novell NetWare(TM) NCP
  protocol.

  A bug was found in the way ncpfs handled file permissions. ncpfs did not
  sufficiently check if the file owner matched the user attempting to access
  the file, potentially violating the file permissions. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-0013 to this issue.

  All users of ncpfs are advised to upgrade to this updated package, which
  contains backported fixes for this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-371.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ipxutils packages";
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
if ( rpm_check( reference:"ipxutils-2.2.0.18-6.EL2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ncpfs-2.2.0.18-6.EL2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ipxutils-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0013", value:TRUE);
}

set_kb_item(name:"RHSA-2005-371", value:TRUE);
