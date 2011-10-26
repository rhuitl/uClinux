#
# (C) Tenable Network Security
#


if (description) {
  script_id(19312);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2405", "CVE-2005-2406", "CVE-2005-2407");
  script_bugtraq_id(14402, 14410, 15835);

  name["english"] = "Opera < 8.02 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote host contains a web browser which is affected by multiple
issues. 

Description :

The remote host is using Opera, an alternative web browser. 

The version of Opera installed on the remote host contains several
flaws.  One involves imaging dragging and could result in cross-site
scripting attacks and user file retrieval.  A second may let attackers
spoof the file extension in the file download dialog provided the
'Arial Unicode MS' font has been installed, which is the case with
various Microsoft Office products.  And a third is a design error in
the processing of mouse clicks in new browser windows that may be
exploited to trick a user into downloading and executing arbitrary
programs on the affected host. 

See also : 

http://secunia.com/advisories/15756/
http://secunia.com/advisories/15870/
http://secunia.com/secunia_research/2005-19/advisory/

Solution : 

Upgrade to Opera 8.02 or later.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Opera < 8.02";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}


ver = get_kb_item("SMB/Opera/Version");
if (ver && ver =~ "^([0-7]\.|8\.0\.[01][^0-9]?)") 
  security_warning(get_kb_item("SMB/transport"));
