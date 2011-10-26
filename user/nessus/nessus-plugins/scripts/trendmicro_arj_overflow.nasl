#
# (C) Tenable Network Security
#
if(description)
{
 script_id(17213);
 script_cve_id("CVE-2005-0533");
 script_bugtraq_id(12643);
 if ( defined_func("script_xref") ) 
	script_xref(name:"IAVA", value:"2005-B-0008");

 script_version("$Revision: 1.6 $");
 name["english"] = "Trend Micro VSAPI ARJ Handling Heap Overflow";
 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running a version of the Trend Micro engine which is
vulnerable to a heap overflow in the ARJ handling functions.

An attacker may exploit this flaw to bypass virus protection altogether and
execute arbitrary code on the remote host. To exploit this flaw, an attacker
would need to submit a malformed ARJ archive to a process on the remote
host and wait for the antivirus engine to scan it.

Solution : Upgrade to the Trend Micro engine version 7.510 or newer.
Risk factor : High";

 script_description(english:desc["english"]);
 summary["english"] = "Checks the version of the remote Trend Micro engine";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security"); 
 family["english"] = "Windows"; 
 script_family(english:family["english"]);
 script_dependencies("trendmicro_installed.nasl");
 script_require_keys("Antivirus/TrendMicro/trendmicro_engine_version");
 exit(0);
}

version = get_kb_item("Antivirus/TrendMicro/trendmicro_engine_version");
if ( ! version ) exit(0);
if ( int(version) < 7510 ) security_hole(0);
