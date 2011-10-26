#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# based on work from
# (C) Tenable Network Security
#
# Ref: Chris Covell and Gottfried Scheckenbach
#

if (description) {
  script_id(14714);
  script_bugtraq_id(9123);
  script_cve_id("CVE-2003-0960");
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"2884");
  script_version ("$Revision: 1.2 $"); 
  name["english"] = "OpenCA multiple signature validation bypass";
  script_name(english:name["english"]);
  desc["english"] = "
The remote host seems to be running an older version of OpenCA. 

It is reported that OpenCA versions up to and incluing 0.9.1.3 contains 
multiple flaws that may allow revoked or expired certificates to be accepted as valid.
 

Solution : Upgrade to the newest version of this software
Risk Factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for the version of OpenCA";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("openca_html_injection.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

version = get_kb_item("www/" + port + "/openca/version");
if ( ! version ) exit(0);


if ( egrep(pattern:"(0\.[0-8]\.|0\.9\.(0|1$|1\.[1-3][^0-9]))", string:version) ) security_warning(port);

