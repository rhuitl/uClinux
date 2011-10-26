#
# (C) Tenable Network Security
#


if (description) {
  script_id(20950);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2341", "CVE-2006-0761");
  script_bugtraq_id(16098, 16590);

  script_name(english:"BlackBerry Enterprise Server Attachment Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks version number of BlackBerry Enterprise Server");
 
  desc = "
Synopsis :

The remote Windows application is affected by multiple buffer overflow
vulnerabilities. 

Description :

The version of BlackBerry Enterprise Server on the remote host
reportedly contains flaws in its handling of Word and TIFF document
attachments that may result in buffer overflows when a user opens a
malformed file on a BlackBerry device.  A remote attacker may be able
to exploit this issue to execute code on the affected host subject to
the privileges under which the application runs, generally
'Administrator'. 

See also :

http://blogs.washingtonpost.com/securityfix/2006/01/security_hole_e.html
http://www.nessus.org/u?c224cef8
http://www.nessus.org/u?f9d6cf39

Solution :

Install the appropriate service pack / hotfix as described in the
vendor advisory referenced above. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("blackberry_es_installed.nasl");
  script_require_keys("BlackBerry_ES/Product", "BlackBerry_ES/Version");

  exit(0);
}


include("smb_func.inc");


prod = get_kb_item("BlackBerry_ES/Product");
ver = get_kb_item("BlackBerry_ES/Version");
if (prod && ver) {
  if (
    (
      "Domino" >< prod && 
      # fixed in 4.0.3 Hotfix 4 (Bundle 18)
      ver =~ "^([0-3]\..*|4\.0\.([0-2].*|3( Hotfix [1-3])?)) \(Bundle"
    ) ||
    (
      "Exchange" >< prod && 
      # fixed in 4.0.3 Hotfix 3 (Bundle 16)
      ver =~ "^([0-3]\..*|4\.0\.([0-2].*|3( Hotfix [12])?)) \(Bundle"
    ) ||
    (
      "GroupWise" >< prod && 
      # fixed in 4.0.3 Hotfix 1 (Bundle 17)
      ver =~ "^([0-3]\..*|4\.0\.([0-2].*|3)) \(Bundle"
    )
  ) {
    security_warning(kb_smb_transport());
  }
}
