#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12376);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2003-0102");

 name["english"] = "RHSA-2003-087: file";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated file packages are available to close a buffer overflow
  vulnerability.

  [Updated 12 March 2003]
  Added packages for Red Hat Enterprise Linux ES and Red Hat Enterprise
  Linux WS

  The file command is used to identify a particular file according to
  the type of data contained by the file.

  The file utility before version 3.41 contains a buffer overflow
  vulnerability in the ELF parsing routines. This vulnerability may
  allow an attacker to create a carefully crafted binary which can cause
  arbitrary code to run if a victim runs the file command against that
  binary.

  On some distributions it may also be possible to trigger this file command
  vulnerability by encouraging the victim to use the
  less command on an exploited file name so that it will be processed by the
  lesspipe.sh script.

  All users are advised to update to these erratum packages which
  contain a backported patch to correct this vulnerability.

  Red Hat would like to thank iDefense for disclosing this issue and
  zen-parse for discussion of some of the implications.




Solution : http://rhn.redhat.com/errata/RHSA-2003-087.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the file packages";
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
if ( rpm_check( reference:"file-3.39-8.7x", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"file-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0102", value:TRUE);
}

set_kb_item(name:"RHSA-2003-087", value:TRUE);
