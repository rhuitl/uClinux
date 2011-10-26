#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16385);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0089");

 name["english"] = "RHSA-2005-109: python";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Python packages that fix a security issue are now available for Red
  Hat Enterprise Linux 3.

  Python is an interpreted, interactive, object-oriented programming
  language.

  An object traversal bug was found in the Python SimpleXMLRPCServer. This
  bug could allow a remote untrusted user to do unrestricted object traversal
  and allow them to access or change function internals using the im_* and
  func_* attributes. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-0089 to this issue.

  Users of Python are advised to upgrade to these updated packages, which
  contain backported patches to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-109.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the python packages";
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
if ( rpm_check( reference:"python-2.2.3-6.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-devel-2.2.3-6.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"python-tools-2.2.3-6.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tkinter-2.2.3-6.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"python-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0089", value:TRUE);
}

set_kb_item(name:"RHSA-2005-109", value:TRUE);
