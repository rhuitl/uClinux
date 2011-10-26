#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18214);
 script_version ("$Revision: 1.4 $");
 script_bugtraq_id(13565);
 script_cve_id("CVE-2005-1248");
 name["english"] = "iTunes < 4.8.0";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of iTunes which is older than
version 4.8.0

The remote version of this software is vulnerable to a buffer overflow
when it parses a malformed MP4 file.

Solution : Upgrade to iTunes 4.8.0
See also : http://www.securityfocus.com/advisories/8545
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check the version of iTunes";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("macosx_iTunes_Overflow.nasl");
 script_require_keys("iTunes/Version");
 exit(0);
}


version = get_kb_item("iTunes/Version");
if ( ! version ) exit(0);
if ( egrep(pattern:"^4\.([0-7]\..*)$", string:version )) security_hole(port); 
