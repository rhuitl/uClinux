#
#  (C) Tenable Network Security
#

if(description)
{
 script_id(15821);

 script_bugtraq_id(11726, 11766);
 script_cve_id("CVE-2004-1029");
 script_xref(name:"IAVA", value:"2004-b-0015");
 script_xref(name:"OSVDB", value:"12095");

 script_version("$Revision: 1.7 $");

 name["english"] = "Sun JRE Java Plug-in JavaScript Security Restriction Bypass";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a vulnerable version of Sun Java Runtime
Plug-in, an addon to many web browser like Internet Explorer to
display java applets.

It has been reported that the Java JRE Plug-in Security can be bypassed.
As a result, an attacker may be able to exploit it by creating a malicious
Java applet to compromise the computer.

Additionally, a denial of service vulnerability is present in the remote
version of the JVM. An attacker could exploit it by creating an applet
which misuses the serialization API.

Solution: Upgrade to JRE 1.4.2_06 or 1.3.1_13
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Java JRE plugin";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("java_jre_version_invocation.nasl");
 script_require_keys("SMB/Java/JRE/Version");
 exit(0);
}




version = get_kb_item("SMB/Java/JRE/Version");
if ( ! version ) exit(0);

if(egrep(pattern:"^1\.(3\.(0.*|1[^_].*|1_[0-9][^0-9].*|1_1[0-2].*)|4\.([0-1]\..*|2_0[0-5].*))", string:version)) security_hole(port);


		
