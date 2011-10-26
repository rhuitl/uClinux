#
# Copyright (C) 2005 Tenable Network Security
#
if(description)
{
 script_id(17159);
 script_bugtraq_id(12601);

 script_version("$Revision: 1.1 $");
 name["english"] = "PuTTY Multiple Integer Overflow Vulnerablities"; 

 script_name(english:name["english"]);


 desc["english"] = "
The remote host is using PuTTY, a free SSH client.

The remote version of this software is vulnerable to various integer overflow
vulnerabilities which may allow an attacker to execute arbitrary code on the remote
host.

To exploit these vulnerabilities, an attacker would need to set up a rogue SSH
daemon and lure a victim on the remote host into connecting to it using PuTTY.

Solution : Upgrade to PuTTY 0.57 or newer
Risk factor : High";



 script_description(english:desc["english"]);

 summary["english"] = "PuTTY version check";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("putty_version_check.nasl");
 script_require_keys("SMB/PuTTY/version");
 exit(0);
}


version = get_kb_item("SMB/PuTTY/version");
if ( ! version ) exit(0);
if ( ereg(pattern:"^([0-4]|5[0-6]([^0-9]|$))", string:version) )
	security_hole(0);
