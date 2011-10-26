#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13853);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0557");

 name["english"] = "RHSA-2004-409: sox";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated sox packages that fix buffer overflows in the WAV file handling
  code are now available.

  SoX (Sound eXchange) is a sound file format converter. SoX can convert
  between many different digitized sound formats and perform simple sound
  manipulation functions, including sound effects.

  Buffer overflows existed in the parsing of WAV file header fields. It was
  possible that a malicious WAV file could have caused arbitrary code to be
  executed when the file was played or converted. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2004-0557
  to these issues.

  All users of sox should upgrade to these updated packages, which resolve
  these issues as well as fix a number of minor bugs.




Solution : http://rhn.redhat.com/errata/RHSA-2004-409.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sox packages";
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
if ( rpm_check( reference:"sox-12.17.4-4.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sox-devel-12.17.4-4.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"sox-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0557", value:TRUE);
}

set_kb_item(name:"RHSA-2004-409", value:TRUE);
