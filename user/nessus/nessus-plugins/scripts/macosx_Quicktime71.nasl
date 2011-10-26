#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);

if (description)
{
  script_id(21554);
  script_version("$Revision: 1.4 $");

  #script_cve_id("CVE-2006-1458", "CVE-2006-1459", "CVE-2006-1460");
  script_bugtraq_id(17953);

  script_name(english:"Quicktime < 7.1 (Mac OS X)");
  script_summary(english:"Checks version of Quicktime on Mac OS X");
 
  desc = "
Synopsis :

The remote version of QuickTime is affected by multiple overflow
vulnerabilities. 

Description :

The remote Mac OS X host is running a version of Quicktime prior to
7.1. 

The remote version of Quicktime is vulnerable to various integer and
buffer overflows involving specially-crafted image and media files. 
An attacker may be able to leverage these issues to execute arbitrary
code on the remote host by sending a malformed file to a victim and
having him open it using QuickTime player. 

See also : 

http://lists.grok.org.uk/pipermail/full-disclosure/2006-May/045979.html
http://lists.grok.org.uk/pipermail/full-disclosure/2006-May/045981.html
http://docs.info.apple.com/article.html?artnum=303752

Solution :

Upgrade to Quicktime version 7.1 or later.

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("macosx_Quicktime652.nasl");
 script_require_keys("MacOSX/QuickTime/Version");


  exit(0);
}


ver = get_kb_item("MacOSX/QuickTime/Version");
if ( ! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);

if ( int(version[0]) == 7 &&  int(version[1]) == 0 )
		security_hole( port );
