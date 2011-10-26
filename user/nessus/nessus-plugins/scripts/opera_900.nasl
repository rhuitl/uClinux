#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21786);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-3198", "CVE-2006-3331");
  script_bugtraq_id(18594, 18692);

  script_name(english:"Opera < 9.00 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  desc = "
Synopsis :

The remote host contains a web browser which is susceptible to multiple
issues.

Description :

The version of Opera installed on the remote host reportedly contains
an issue that presents itself when the height and width parameters of
a JPEG image are set excessively high, causing Opera to allocate
insufficient memory for the image and crash as it tries to write to
memory at the wrong location. 

In addition, it is reportedly affected by a flaw that may allow an
attacker to display an SSL certificate from a trusted site on an
untrusted one. 

See also :

http://www.securityfocus.com/archive/1/438074/30/0/threaded
http://www.opera.com/support/search/supsearch.dml?index=834
http://secunia.com/secunia_research/2006-49/advisory/

Solution :

Upgrade to Opera version 9.00 or later.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}


ver = get_kb_item("SMB/Opera/Version");
if (ver && ver =~ "^[0-8]\.")
  security_warning(get_kb_item("SMB/transport"));
