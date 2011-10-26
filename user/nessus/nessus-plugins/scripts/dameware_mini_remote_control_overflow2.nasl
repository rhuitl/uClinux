#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19554);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2005-2842");
 script_bugtraq_id(14707);

 name["english"] = "DameWare Mini Remote Control Pre-Authentication Username Buffer Overflow Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running DameWare Mini Remote Control. The
remote version of this software is vulnerable to a buffer
overflow vulnerability.
An attacker may be able to exploit this flaw by sending a
specially crafted packet to the remote host.

A successful exploitation of this vulnerability would result
in remote code execution.

Solution :

Upgrade to version 4.9.0.0 or later.

Risk Factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines version of DameWare Mini Remote Control (Overflow2)";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_require_ports(6129, "Services/dameware");
 script_dependencies("dameware_mini_remote_control_overflow.nasl");
 script_require_keys("DameWare/major_version", "DameWare/minor_version");
 exit(0);
}

port = get_kb_item("Services/dameware");
if (! port) port = 6129;

major = get_kb_item ("DameWare/major_version");
minor = get_kb_item ("DameWare/minor_version");

if (isnull(major) || isnull(minor))
  exit (0);
if (((major == 3) && (minor >= 23920)) || ((major == 4) && (minor < 14745)))
  security_hole (port:port);

