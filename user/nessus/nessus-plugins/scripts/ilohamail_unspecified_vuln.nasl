#
# (C) Tenable Network Security
#

if (description) {
  script_id(15935);
  script_cve_id("CVE-2004-2500");
  script_bugtraq_id(11872);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"12292");
  }
  script_version("$Revision: 1.3 $");

  name["english"] = "IlohaMail Unspecified Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of IlohaMail version
0.8.13 or earlier. 

The remote version of this software is vulnerable to an unspecified
vulnerability announced by the vendor.

See also : http://sourceforge.net/project/shownotes.php?group_id=54027&release_id=288409
Solution : Upgrade to IlohaMail version 0.8.14RC1 or later.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks the version if Ilohamail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

kb = get_kb_list("www/" + port + "/ilohamail");
if (isnull( kb )) exit(0);


foreach item (kb) 
{
  matches = eregmatch(string:item, pattern:"^(.+) under (.*)$");
  if ( ereg(pattern:"^0\.([0-7]\.|8\.([0-9][^0-9]|1[0-3]))", string:matches[1]) )
	{
	security_hole(port);
	exit(0);
	}
}
