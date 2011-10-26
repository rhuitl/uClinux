#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20746);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2006-0306", "CVE-2006-0307");
 script_bugtraq_id(16276);
 script_xref(name:"OSVDB", value:"22529");

 name["english"] = "DM Deployment Common Component Vulnerabilities";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

It is possible to cause a denial of service against the remote
service.

Description :

The remote version of DMPrimer service (Computer Associates DM 
Deployment Common Component) is vulnerable to multiple Denial
of Service attacks.
An attacker can crash or may cause a high CPU utilization by
sending a specially crafted UDP packets.

See also :

http://supportconnectw.ca.com/public/ca_common_docs/dmdeploysecurity_notice.asp

Solution :

Disable the DMPrimer service.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";


 script_description(english:desc["english"]);

 summary["english"] = "Determines the version of the remote DMPrimer service";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);

 script_dependencies("dmprimer_detect.nasl");
 script_require_keys("CA/DMPrimer");
 script_require_ports(5727);
 exit(0);
}

version = get_kb_item ("CA/DMPrimer");

if (!isnull (version) &&
    ( (version == "1.4.154") || (version == "1.4.155") ) )
  security_note(5727);
