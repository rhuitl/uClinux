#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20840);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2006-0529", "CVE-2006-0530");
 script_bugtraq_id(16475);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"21146");
 }

 name["english"] = "Computer Associates Message Queuing Denial Of Service Vulnerabilities";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

It is possible to crash the remote messaging service.

Description :

The remote version of Computer Associates Message Queuing Service
is vulnerable to tow flaws which may lead to a denial of service :

- Improper handling of specially crafted TCP packets on port 4105
- Failure to handle spoofed UDP CAM requests
 
See also :

http://supportconnectw.ca.com/public/ca_common_docs/camsecurity_notice.asp

Solution :

Computer Associates has released a set of patches for CAM 1.05, 1.07
and 1.11. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";

 script_description(english:desc["english"]);

 summary["english"] = "Determines if the remote CAM service is vulnerable to a DoS";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
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
# < 1.07 build 220_16
# 1.07 build 230 & 231
# < 1.11 build 29_20

if ( (main < 1) ||
     ((main == 1) && (revision < 7)) ||
     ((main == 1) && (revision > 7) && (revision < 11)) )
{
 security_note(port);
}
else if (main == 1)
{
 if (revision == 7)
 {
  if ( (build < 220) ||
       ( (build == 220) && (build_rev < 16) ) )
    security_note(port);
  else if ((build == 230) || (build == 231))
    security_note(port);
 }
 else if (revision == 11)
 {
  if ( (build < 29) ||
       ( (build == 29) && (build_rev < 20) ) )
    security_note(port);
 }
}
