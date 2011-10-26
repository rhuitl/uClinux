#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11857);
 script_bugtraq_id(6186);
 script_version("$Revision: 1.3 $");
 script_cve_id("CVE-2002-0029");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0012");
 
 name["english"] = "BIND Buffer overflows in the DNS stub resolver library ";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote BIND 4.x server, according to its version number, is vulnerable to a 
buffer overflow in the DNS stub resolver library.

Solution : upgrade to latest or patched version of BIND 
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks that BIND is not version 4.9.2 through 4.9.10";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) Tenable Security",
		francais:"Ce script est Copyright (C) Tenable Security");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

vers = get_kb_item("bind/version");
if(!vers)exit(0);
if (vers =~ "^4\.9\.[2-9]") security_hole(53); 
if (vers =~ "^4\.9\.10") security_hole(53);


