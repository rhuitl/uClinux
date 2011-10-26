#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22311);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4095", "CVE-2006-4096");
  script_bugtraq_id(19859);

  script_name(english:"BIND 9 Denial of Service Vulnerabilities");
  script_summary(english:"Checks version of BIND");

  desc = "
Synopsis :

The remote name server may be affected by multiple denial of service
vulnerabilities. 

Description :

The version of BIND installed on the remote host suggests that it
suffers from multiple denial of service vulnerabilities, which may be
triggered by either by sending a large volume of recursive queries or
queries for SIG records where there are multiple SIG(covered) RRsets. 

Note that Nessus obtained the version by sending a special DNS request
for the text 'version.bind' in the domain 'chaos', the value of which
can be and sometimes is tweaked by DNS administrators. 

See also :

http://www.niscc.gov.uk/niscc/docs/re-20060905-00590.pdf?lang=en
http://www.isc.org/index.pl?/sw/bind/bind-security.php

Solution :

Upgrade to BIND 9.4.0b2 / 9.3.3rc2 / 9.3.2-P1 / 9.2.7rc2 / 9.2.6-P1 or
later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version");

  exit(0);
}


include("global_settings.inc");


# Banner checks of BIND are prone to false-positives so we only
# run the check if reporting is paranoid.
if (report_paranoia <= 1) exit(0);


ver = get_kb_item("bind/version");
if (!ver) exit(0);

if (ver =~ "^9\.(2\.([0-5][^0-9]?|6(b|rc|$)|7(b|rc1))|3\.([01][^0-9]?|2(b|rc|$)|3(b|rc1))|4\.0b1)")
  security_note(53);
