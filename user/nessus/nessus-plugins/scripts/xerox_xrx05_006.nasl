#
# (C) Tenable Network Security
#


if (description) {
  script_id(18642);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2200", "CVE-2005-2201", "CVE-2005-2202");
  script_bugtraq_id(14187);
  script_xref(name:"OSVDB", value:"17765");
  script_xref(name:"OSVDB", value:"17766");

  name["english"] = "Xerox WorkCentre Pro Multiple Remote Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote printer suffers from multiple vulnerabilities. 

Description :

According to its model number and software versions, the remote host
is a Xerox WorkCentre device with an embedded web server that suffers
from multiple flaws, including authentication bypass, denial of
service, unauthorized file access, and cross-site scripting. 

See also : 

http://www.xerox.com/downloads/usa/en/c/cert_XRX05_006.pdf
http://www.xerox.com/downloads/usa/en/c/cert_XRX05_007.pdf

Solution : 

Apply the P22 patch as described in the Xerox security bulletins. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple remote vulnerabilities in Xerox WorkCentre Pro";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("xerox_workcentre_detect.nasl");

  exit(0);
}


# This function returns TRUE if the version string ver lies in
# the range [low, high].
function ver_inrange(ver, low, high) {
  local_var ver_parts, low_parts, high_parts, i, p, low_p, high_p;

  if (isnull(ver) || isnull(low) || isnull(high)) return FALSE;

  # Split levels into parts.
  ver_parts = split(ver, sep:".", keep:0);
  low_parts = split(low, sep:".", keep:0);
  high_parts = split(high, sep:".", keep:0);

  # Compare each part.
  i = 0;
  while (ver_parts[i] != NULL) {
    p = int(ver_parts[i]);
    low_p = int(low_parts[i]);
    if (low_p == NULL) low_p = 0;
    high_p = int(high_parts[i]);
    if (high_p == NULL) high_p = 0;

    if (p > low_p && p < high_p) return TRUE;
    if (p < low_p || p > high_p) return FALSE;
    ++i;
  }
  return TRUE;
}


# Check whether the device is vulnerable.
device = get_kb_item("www/workcentre");
if (device) {
  matches = eregmatch(string:device, pattern:"^(.+), SCD (.*), ESS (.*)$");
  if (isnull(matches)) exit(0);

  model = matches[1];
  scd = matches[2];
  ess = matches[3];

  # No need to check further if ESS has with ".P22" since that
  # indicates the patch has already been applied.
  if (ess =~ "\.P22[^0-9]?") exit(0);

  # Test model number and software version against those in Xerox's security bulletin.
  if (
    # nb: models Pro 2128/2636/3545 Color with SCD 0.001.04.044 - 0.001.04.504.
    model =~ "Pro (32|40)C" && ver_inrange(ver:scd, low:"0.001.04.044", high:"0.001.04.504")
  ) security_hole(0);
}
