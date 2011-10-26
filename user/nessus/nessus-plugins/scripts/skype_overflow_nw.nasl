#
# (C) Tenable Network Security
#


# This script depends on a .nbin plugin
if ( NASL_LEVEL < 3000 ) exit(0);

if (description)
{
 script_id(21209);
 script_version("$Revision: 1.4 $");

 script_cve_id("CVE-2005-3265", "CVE-2005-3267");
 script_bugtraq_id(15190, 15192);
 script_xref(name:"OSVDB", value:"20306");

 name["english"] = "Skype Networking Routine Heap Overflow Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running Skype, a peer-to-peer voice over IP
software. 

The remote version of this software is vulnerable to a Heap overflow
in the handling of its data structures.  An attacker can exploit this
flaw by sending a specially crafted network packet to UDP or TCP ports
Skype is listenning on. 

A successful exploitation of this flaw will result in code execution
on the remote host. 

See also : 

http://www.skype.com/security/skype-sb-2005-03.html

Solution :

Upgrade to skype version 1.4.0.84 or later.

Risk factor :

High / CVSS Base Score : 8
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Skype Heap overflow for Windows";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain root remotely");

 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

 script_dependencies("skype_version.nbin");
 script_require_keys("Services/skype");

 exit(0);
}



port = get_kb_item("Services/skype");
if ( ! port ) exit(0);

ts = get_kb_item("Skype/" + port + "/stackTimeStamp");
if ( ! ts ) exit(0);

if ( ts < 510211313 ) security_hole ( port );
