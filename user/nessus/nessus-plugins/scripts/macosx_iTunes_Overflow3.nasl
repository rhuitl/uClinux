#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21781);
 script_version ("$Revision: 1.5 $");
 script_bugtraq_id(18730);
 script_cve_id("CVE-2006-1467");
 name["english"] = "iTunes AAC File Integer Overflow Vulnerability  (Mac OS X)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host contains an application that is affected by a remote
code execution flaw. 

Description :

The remote host is running iTunes, a popular jukebox program.

The remote version of this software is vulnerable to an integer
overflow when it parses specially crafted AAC files which may 
lead to the execution of arbitrary code.

An attacker may exploit this flaw by sending a malformed AAC
file to a user on the remote host and wait for him to play it
with iTunes.

See also :

http://www.securityfocus.com/advisories/10781

Solution :

Upgrade to iTunes 6.0.5 or newer

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check the version of iTunes";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("macosx_iTunes_Overflow.nasl");
 script_require_keys("iTunes/Version");
 exit(0);
}


version = get_kb_item("iTunes/Version");
if ( ! version ) exit(0);
if ( egrep(pattern:"^([1-5]\..*|6\.0($|\.[0-4]$))", string:version )) security_warning(port); 
