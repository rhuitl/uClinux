#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12411);
 script_bugtraq_id(8144);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0539");

 name["english"] = "RHSA-2003-242: ddskk";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has an old version of the ddskk package installed.

ddskk (Daredevil SKK) is a Kana to Kanji conversion program. There is a bug
in the remote version of this package in the way it creates temporary files
which may allow a local attacker to overwrite arbitrary files owned by the
user using ddskk.

Solution : https://rhn.redhat.com/errata/RHSA-2003-242.html
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ddskk package";
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


if ( rpm_check( reference:"ddskk-11.6.0-1.7.ent",yank:".ent", release:"RHEL2.1"))
	security_warning(0);
