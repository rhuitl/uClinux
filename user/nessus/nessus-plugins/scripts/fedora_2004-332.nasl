#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15454);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0884");
 
 name["english"] = "Fedora Core 2 2004-332: cyrus-sasl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-332 (cyrus-sasl).

The cyrus-sasl package contains the Cyrus implementation of SASL.
SASL is the Simple Authentication and Security Layer, a method for
adding authentication support to connection-based protocols.

Update Information:

At application startup, libsasl and libsasl2 attempt to build a list
of all SASL plug-ins which are available on the system.  To do so,
the libraries search for and attempt to load every shared library
found within the plug-in directory.  This location can be set with
the SASL_PATH environment variable.

In situations where an untrusted local user can affect the
environment of a privileged process, this behavior could be exploited
to run arbitrary code with the privileges of a setuid or setgid
application.  The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0884 to this issue.

Users of cyrus-sasl should upgrade to these updated packages, which
contain backported patches and are not vulnerable to this issue.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-332.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cyrus-sasl package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cyrus-sasl-2.1.18-2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-devel-2.1.18-2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-gssapi-2.1.18-2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-plain-2.1.18-2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-md5-2.1.18-2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cyrus-sasl-debuginfo-2.1.18-2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"cyrus-sasl-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0884", value:TRUE);
}
