#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16085);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2004-1316");
 script_bugtraq_id(12131, 12407);
 script_xref(name:"OSVDB", value:"12637");

 name["english"] = "Mozilla Browser Network News Transport Protocol Remote Heap Overflow Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A web browser on the remote host is prone to a heap overflow vulnerability.

Description :

The remote version of Mozilla is vulnerable to a heap overflow
vulnerability against its NNTP functionality. 

This may allow an attacker to execute arbitrary code on the remote
host. 

To exploit this flaw, an attacker would need to set up a rogue news
site and lure a victim on the remote host into reading news from it. 

See also :

http://www.mozilla.org/security/announce/mfsa2005-06.html

Solution : 

Upgrade to Mozilla 1.7.5 or newer.

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Mozilla";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("mozilla_org_installed.nasl");
 exit(0);
}


moz = get_kb_item("Mozilla/Version");
if (!moz) exit(0);

ver = split(moz, sep:'.', keep:FALSE);
if (
  int(ver[0]) < 1 ||
  (
    int(ver[0]) == 1 &&
    (
      int(ver[1]) < 7 ||
      (int(ver[1]) == 7 && int(ver[2]) < 5)
    )
  )
)  security_hole(get_kb_item("SMB/transport"));
