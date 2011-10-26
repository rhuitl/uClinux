#
# Copyright (C) 2004 Tenable Network Security
#
if(description)
{
 script_id(14686);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2004-1666");
 script_bugtraq_id(11142);

 name["english"] = "Trillian MSN Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
Trillian is a Peer2Peer client that allows users to chat and share files
with other users across the world.  A bug has been reported in the MSN 
portion of Trillian.  

A remote attacker, exploiting this flaw, would be potentially able to execute 
code on the client system running Trillian.

Solution: Upgrade to Trillian 0.74 patch J (or higher).
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Trillian.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("trillian_patchg.nasl");
 script_require_keys("Host/Windows/Trillian/Version");
 exit(0);
}


version = get_kb_item("Host/Windows/Trillian/Version");

if (egrep(string:version, pattern:"v0\.7[1-4].*")) {
    if (! egrep(string:version, pattern:"\(w/ Patch [J-Z]\)")) security_hole(port);
}
