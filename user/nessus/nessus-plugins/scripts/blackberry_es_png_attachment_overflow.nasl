#
# (C) Tenable Network Security
#


if (description) {
  script_id(20982);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-2344");
  script_bugtraq_id(16204);

  script_name(english:"BlackBerry Enterprise Server PNG Attachment Buffer Overflow Vulnerability");
  script_summary(english:"Checks version number of BlackBerry Enterprise Server");
 
  desc = "
Synopsis :

The remote Windows application is affected by a buffer overflow
vulnerability. 

Description :

The version of BlackBerry Enterprise Server installed on the remote
host reportedly is affected by a heap-based buffer overflow that can
be triggered by a malformed PNG attachment.  Exploitation of this
issue may cause the Attachment Service to stop responding or crash and
may even allow for the execute of arbitrary code subject to the
privileges under which the application runs, generally
'Administrator'. 

See also :

http://www.nessus.org/u?c10eb5db

Solution :

Install the appropriate service pack / hotfix as described in the
vendor advisory referenced above. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("blackberry_es_installed.nasl");
  script_require_keys("BlackBerry_ES/Product", "BlackBerry_ES/Version");

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


prod = get_kb_item("BlackBerry_ES/Product");
ver = get_kb_item("BlackBerry_ES/Version");
if (prod && ver) {
  if (
    (
      "Domino" >< prod && 
      ver =~ "^([0-3]\..*|4\.0\.([0-2].*))"
    ) ||
    (
      "Exchange" >< prod && 
      ver =~ "^([0-3]\..*|4\.0\.([0-2].*|3 \(Bundle))"
    ) ||
    (
      "GroupWise" >< prod && 
      ver =~ "^([0-2]\..*|4\.0\.([0-2].*))"
    )
  ) {
    security_note(kb_smb_transport());
  }
}
