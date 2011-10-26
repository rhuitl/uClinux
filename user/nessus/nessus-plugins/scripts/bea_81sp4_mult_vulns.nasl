#
# (C) Tenable Network Security
#


if (description) {
  script_id(18365);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-1380", "CVE-2005-1747");
  script_bugtraq_id(12548, 13400, 13717, 13793, 13794, 14632, 14657);
  script_xref(name:"OSVDB", value:"15895");
  script_xref(name:"OSVDB", value:"16844");

  name["english"] = "BEA WebLogic <= 8.1 SP4 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is affected by multiple flaws.

Description :

According to its banner, the remote host is running a version of BEA
WebLogic Server or WebLogic Express that is prone to multiple
vulnerabilities.  These flaws could lead to buffer overflows, denial
of service, unauthorized access, cross-site scripting attacks, and
information disclosure. 

See also : 

http://dev2dev.bea.com/advisoriesnotifications/

Solution : 

Refer to the advisories in the URL referenced above.

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:L/Au:NR/C:P/A:P/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in BEA WebLogic <= 8.1 SP4";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Check the version number in the banner.
banner = get_http_banner(port:port);
if (!banner || "WebLogic " >!< banner) exit(0);

pat = "^Server:.*WebLogic .*([0-9]+\.[0-9.]+) ";
matches = egrep(pattern:pat, string:banner);
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver)) {
      # Extract the version and service pack numbers.
      nums = split(ver[1], sep:".", keep:FALSE);
      ver_maj = int(nums[0]);
      ver_min = int(nums[1]);

      sp = ereg_replace(
        string:match, 
        pattern:".* (Service Pack |SP)([0-9]+) .+",
        replace:"\2"
      );
      if (!sp) sp = 0;
      else sp = int(sp);

      # Check them against vulnerable versions listed in BEA's advisories.
      if (
        # version 6.x
        (
          ver_maj == 6 && 
          (
            ver_min < 1 ||
            (ver_min == 1 && sp <= 6)
          )
        ) ||

        # version 7.x
        (ver_maj == 7 && (ver_min == 0 && sp <= 6)) ||
  
        # version 8.x
        (
          ver_maj == 8 && 
          (
            ver_min < 1 ||
            (ver_min == 1 && sp <= 4)
          )
        )
      ) {
        security_hole(port);
      }
      exit(0);
    }
  }
}
