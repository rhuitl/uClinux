#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22335);
 script_version ("$Revision: 1.1 $");
 script_bugtraq_id(19976);
 name["english"] = "Quicktime < 7.1.3 (Mac OS X)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote version of QuickTime is affected by multiple overflow
vulnerabilities. 

Description :

The remote Mac OS X host is running a version of Quicktime prior to
7.1.3. 

The remote version of Quicktime is vulnerable to various integer and
buffer overflows involving specially-crafted image and media files. 
An attacker may be able to leverage these issues to execute arbitrary
code on the remote host by sending a malformed file to a victim and
having him open it using QuickTime player. 

See also : 

http://docs.info.apple.com/article.html?artnum=304357

Solution :

Upgrade to Quicktime version 7.1.3 or later.

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Quicktime 7.1.3";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("macosx_Quicktime652.nasl");
 script_require_keys("MacOSX/QuickTime/Version");
 exit(0);
}

ver = get_kb_item("MacOSX/QuickTime/Version");
if (! ver ) exit(0);

version = split(ver, sep:'.', keep:FALSE);
if ( (int(version[0]) < 7) ||
     (int(version[0]) == 7 && int(version[1]) == 0 ) ||
     (int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) < 3) ) security_hole(0);
