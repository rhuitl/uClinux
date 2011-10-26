#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19833);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1487", "CVE-2004-1488", "CVE-2004-2014");

 name["english"] = "RHSA-2005-771: wget";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated wget package that fixes several security issues is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  GNU Wget is a file retrieval utility that can use either the HTTP or
  FTP protocols.

  A bug was found in the way wget writes files to the local disk. If a
  malicious local user has write access to the directory wget is saving a
  file into, it is possible to overwrite files that the user running wget
  has write access to. (CVE-2004-2014)

  A bug was found in the way wget filters redirection URLs. It is possible
  for a malicious Web server to overwrite files the user running wget has
  write access to. Note: in order for this attack to succeed the local
  DNS would need to resolve ".." to an IP address, which is an unlikely
  situation. (CVE-2004-1487)

  A bug was found in the way wget displays HTTP response codes. It is
  possible that a malicious web server could inject a specially crafted
  terminal escape sequence capable of misleading the user running wget.
  (CVE-2004-1488)

  Users should upgrade to this updated package, which contains a version of
  wget that is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-771.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wget packages";
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
if ( rpm_check( reference:"wget-1.10.1-0.AS21", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.10.1-1.30E.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"wget-1.10.1-2.4E.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"wget-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1487", value:TRUE);
 set_kb_item(name:"CVE-2004-1488", value:TRUE);
 set_kb_item(name:"CVE-2004-2014", value:TRUE);
}
if ( rpm_exists(rpm:"wget-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1487", value:TRUE);
 set_kb_item(name:"CVE-2004-1488", value:TRUE);
 set_kb_item(name:"CVE-2004-2014", value:TRUE);
}
if ( rpm_exists(rpm:"wget-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1487", value:TRUE);
 set_kb_item(name:"CVE-2004-1488", value:TRUE);
 set_kb_item(name:"CVE-2004-2014", value:TRUE);
}

set_kb_item(name:"RHSA-2005-771", value:TRUE);
