#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20173);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-T-0031");
 script_version("$Revision: 1.5 $");
 script_bugtraq_id(14621,14622,14623);
 script_cve_id("CVE-2005-2667", "CVE-2005-2668", "CVE-2005-2669");
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"18915");
   script_xref(name:"OSVDB", value:"18916");
   script_xref(name:"OSVDB", value:"18917");
 }

 name["english"] = "Computer Associates Message Queuing Buffer Overflow Vulnerability";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to a flaw in the
CAM service. 

Description :

The remote version of Computer Associates Message Queuing Service
contains a a stack overflow in the 'log_security' function that may
allow an attacker to execute arbitrary code on the remote host. 

This version is also prone to denial of service on the TCP port 4105
as well as arbitrary code execution through spoofed CAFT packets. 

An attacker does not need to be authenticated to exploit this flaw. 

See also :

http://supportconnectw.ca.com/public/ca_common_docs/camsecurity_notice.asp

Solution :

Computer Associates has released a set of patches for CAM 1.05, 1.07
and 1.11. 

Risk factor : 

Critical / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);

 summary["english"] = "Determines if the remote CAM service is vulnerable to a buffer overflow";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);

 script_dependencies("cacam_detect.nasl");
 script_require_keys("CA/MessageQueuing");
 script_require_ports(4105);
 exit(0);
}

version = get_kb_item ("CA/MessageQueuing");
if (isnull(version))
  exit (0);

port = 4105;

main = ereg_replace (pattern:"^([0-9]+)\.[0-9]+ \(Build [0-9]+_[0-9]+\)$", string:version, replace:"\1");
revision = ereg_replace (pattern:"^[0-9]+\.([0-9]+) \(Build [0-9]+_[0-9]+\)$", string:version, replace:"\1");

build = ereg_replace (pattern:"^[0-9]+\.[0-9]+ \(Build ([0-9]+)_[0-9]+\)$", string:version, replace:"\1");
build_rev = ereg_replace (pattern:"^[0-9]+\.[0-9]+ \(Build [0-9]+_([0-9]+)\)$", string:version, replace:"\1");


main = int(main);
revision = int (revision);
build = int(build);
build_rev = int (build_rev);


# vulnerable :
# 1.05
# < 1.07 build 220_13
# 1.07 build 230 & 231
# < 1.11 build 29_13

if ( (main < 1) ||
     ((main == 1) && (revision < 7)) ||
     ((main == 1) && (revision > 7) && (revision < 11)) )
{
 security_hole (port);
}
else if (main == 1)
{
 if (revision == 7)
 {
  if ( (build < 220) ||
       ( (build == 220) && (build_rev < 13) ) )
    security_hole (port);
  else if ((build == 230) || (build == 231))
    security_hole (port);
 }
 else if (revision == 11)
 {
  if ( (build < 29) ||
       ( (build == 29) && (build_rev < 13) ) )
    security_hole (port);
 }
}
