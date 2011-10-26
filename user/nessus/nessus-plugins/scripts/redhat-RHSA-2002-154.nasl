#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12314);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2002-0658");

 name["english"] = "RHSA-2002-154: mm";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mm packages are now available for Red Hat Linux Advanced Server.
  This update addresses possible vulnerabilities in how the MM library
  opens temporary files.

  The MM library provides an abstraction layer which allows related processes
  to easily share data. On systems where shared memory or other
  inter-process communication mechanisms are not available, the MM library
  will emulate them using temporary files. MM is used in Red Hat Linux to
  providing shared memory pools to Apache modules.

  Versions of MM up to and including 1.1.3 open temporary files in an unsafe
  manner, allowing a malicious local user to cause an application which uses
  MM to overwrite any file to which it has write access.

  All users are advised to upgrade to these errata packages which contain a
  patched version of MM that is not vulnerable to this issue.

  Thanks to Marcus Meissner for providing a patch for this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2002-154.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mm packages";
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
if ( rpm_check( reference:"mm-1.1.3-8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mm-devel-1.1.3-8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mm-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0658", value:TRUE);
}

set_kb_item(name:"RHSA-2002-154", value:TRUE);
