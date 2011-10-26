#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:032
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14731);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0032");
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0747", "CVE-2004-0786");
 script_bugtraq_id(11187, 11182);
 
 name["english"] = "SUSE-SA:2004:032: apache2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:032 (apache2).


The Apache daemon is running on most of the web-servers used in the
Internet today.
The Red Hat ASF Security-Team and the Swedish IT Incident Center within
the National Post and Telecom Agency (SITIC) have found a bug in apache2
each.
The first vulnerability appears in the apr_uri_parse() function while
handling IPv6 addresses. The affected code passes a negative length
argument to the memcpy() function. On BSD systems this can lead to remote
command execution due to the nature of the memcpy() implementation.
On Linux this bug will result in a remote denial-of-service condition.
The second bug is a local buffer overflow that occurs while expanding
${ENVVAR} in the .htaccess and httpd.conf file. Both files are not
writeable by normal user by default.



Solution : http://www.suse.de/security/2004_32_apache2.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the apache2 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"apache2-2.0.48-139", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.48-139", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.48-139", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apr-2.0.48-139", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-perchild-2.0.48-139", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-2.0.48-139", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.48-139", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.48-139", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.48-139", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-leader-2.0.48-139", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-2.0.48-139", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.48-139", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.48-139", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.48-139", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-leader-2.0.48-139", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-metuxmpm-2.0.48-139", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-2.0.49-27.14", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-prefork-2.0.49-27.14", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-worker-2.0.49-27.14", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"libapr0-2.0.49-27.14", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"apache2-", release:"SUSE8.1")
 || rpm_exists(rpm:"apache2-", release:"SUSE8.2")
 || rpm_exists(rpm:"apache2-", release:"SUSE9.0")
 || rpm_exists(rpm:"apache2-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0747", value:TRUE);
 set_kb_item(name:"CVE-2004-0786", value:TRUE);
}
