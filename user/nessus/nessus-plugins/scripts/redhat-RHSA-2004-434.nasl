#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14802);
 script_bugtraq_id(11240);
 script_cve_id("CVE-2004-0750");
 script_version ("$Revision: 1.2 $");
 name["english"] = "RHSA-2004-434: redhat-config-nfs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is running a version of the redhat-config-nfs package which is 
older than redhat-config-nfs-1.0.13-6.

The redhat-config-nfs package includes a graphical user interface for
creating, modifying, and deleting nfs shares.

John Buswell discovered a flaw in redhat-config-nfs that could lead to
incorrect permissions on exported shares when exporting to multiple
hosts. This could cause an option such as "all_squash" to not be
applied to all of the listed hosts. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-0750 to
this issue.

Additionally, a bug was found that prevented redhat-config-nfs from being
run if hosts didn\'t have options set in /etc/exports.

All users of redhat-config-nfs are advised to upgrade to these updated
packages as well as checking their NFS shares directly or via the
/etc/exports file for any incorrectly set options.


Solution : https://rhn.redhat.com/errata/RHSA-2004-467.html
Risk factor : Medium';


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the redhat-config-nfs package";
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

if ( rpm_check( reference:"redhat-config-nfs-1.0.13-6", release:"RHEL3") ) 
	security_warning(0);
