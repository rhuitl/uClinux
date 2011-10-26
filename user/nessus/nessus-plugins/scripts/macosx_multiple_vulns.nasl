#
# (C) Tenable Network Security
#
if(description) {
 script_id(12257);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0004");
 script_bugtraq_id(10268, 10271, 10432);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0430");


 name["english"] = "Multiple MacOS X vulnerabilties";
 script_name(english:name["english"]);

 desc["english"] ="
The remote host is running a version of MacOS which is older than 10.3.4.

Versions older than 10.3.4 contain several flaws which may allow an attacker
to execute arbitrary commands on the remote system with root privileges.

Solution : Upgrade to MacOS X 10.3.4
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Various flaws in MacOS X";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("os_fingerprint.nasl");
 exit(0);
}


# The Operating system is actually very detailed, because we can read
# its exact version using NTP or RendezVous
os = get_kb_item("Host/OS/icmp");
if ( ! os || "Mac OS X" >!< os ) exit(0);

if ( egrep(pattern:"Mac OS X 10\.([01]\.|3\.[0-3])", string:os) )
	security_hole(0);

