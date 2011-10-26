#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:075-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14058);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(8134, 8135, 8137);
 script_cve_id("CVE-2003-0192", "CVE-2003-0253", "CVE-2003-0254");
 
 name["english"] = "MDKSA-2003:075-1: apache2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:075-1 (apache2).


Several vulnerabilities were discovered in Apache 2.x versions prior to 2.0.47.
From the Apache 2.0.47 release notes:
Certain sequences of per-directory renegotiations and the SSLCipherSuite
directive being used to upgrade from a weak ciphersuite to a strong one could
result in the weak ciphersuite being used in place of the new one
(CVE-2003-0192).
Certain errors returned by accept() on rarely accessed ports could cause
temporary Denial of Service due to a bug in the prefork MPM (CVE-2003-0253).
Denial of Service was caused when target host is IPv6 but FTP proxy server can't
create IPv6 socket (CVE-2003-0254).
The server would crash when going into an infinite loop due to too many
subsequent internal redirects and nested subrequests (VU#379828).
The Apache Software Foundation thanks Saheed Akhtar and Yoshioka Tsuneo for
responsibly reporting these issues.
To upgrade these apache packages, first stop Apache by issuing, as root:
service httpd stop
After the upgrade, restart Apache with:
service httpd start
Update:
The previously released packages had a manpage conflict between apache2-common
and apache-1.3 that prevented both packages from being installed at the same
time. This update provides a fixed apache2-common package.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:075-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache2 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"apache2-common-2.0.47-1.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"apache2-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0192", value:TRUE);
 set_kb_item(name:"CVE-2003-0253", value:TRUE);
 set_kb_item(name:"CVE-2003-0254", value:TRUE);
}
