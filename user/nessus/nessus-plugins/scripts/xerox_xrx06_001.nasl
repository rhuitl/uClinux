#
# (C) Tenable Network Security
#


if (description) {
  script_id(20951);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-0825", "CVE-2006-0826", "CVE-2006-0827", "CVE-2006-0828");
  script_bugtraq_id(16723, 16726, 16727);
  script_xref(name:"OSVDB", value:"23359");

  script_name(english:"Xerox XRX06-001");
  script_summary(english:"Checks for multiple ESS / network controller and microServer vulnerabilities in Xerox WorkCentre devices");

  desc = "
Synopsis :

The remote device is affected by multiple vulnerabilities. 

Description :

According to its model number and software versions, the remote host
is a Xerox WorkCentre device that reportedly is affected by several
issues, including authentication bypass / unauthorized network access,
denial of service when handling malformed Postscript files, an
unspecified cross-site scripting issue, and unspecified errors that
might reduce the effectiveness of certain security features. 

See also :

http://www.xerox.com/downloads/usa/en/c/cert_XRX06_001.pdf

Solution :

Contact Xerox and request the solution for Security Bulletin Number
XRX06-001. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

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

  # Test model number and software version against those in Xerox's security bulletin.
  if (
    # nb: models 232/238/245/255/265/275 with SCD < 14.027.24.015.
    (
      model =~ "2(32|38|45|55|65|75)" && 
      ver_inrange(ver:scd, low:"0", high:"14.027.24.015")
    ) ||
    # nb: models 232/238/245/255/265/275 with SCD < 14.027.24.015.
    (
      model =~ "Pro 2(32|38|45|55|65|75)" && 
      ver_inrange(ver:scd, low:"0", high:"13.027.24.015")
    )
  ) security_warning(0);
}
