#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12436);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1565");

 name["english"] = "RHSA-2003-372: wget";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated wget packages that correct a buffer overrun are now available.

  GNU Wget is a file-retrieval utility that uses the HTTP and FTP protocols.

  A buffer overflow in the url_filename function for wget 1.8.1 allows
  attackers to cause a segmentation fault via a long URL. Red Hat does not
  believe that this issue is exploitable to allow an attacker to be able to
  run arbitrary code. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2002-1565 to this issue.

  Users of wget should install the erratum package, which contains a
  backported security patch and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-372.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the wget packages";
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
if ( rpm_check( reference:"wget-1.8.2-14.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"wget-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1565", value:TRUE);
}

set_kb_item(name:"RHSA-2003-372", value:TRUE);
