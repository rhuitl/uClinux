#
# (C) Tenable Network Security
#


if (description) {
  script_id(19549);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2645", "CVE-2005-2645", "CVE-2005-2647");
  script_bugtraq_id(14586);
  script_xref(name:"OSVDB", value:"17765");
  script_xref(name:"OSVDB", value:"17766");

  name["english"] = "Xerox MicroServer Web Server Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote printer suffers from multiple vulnerabilities. 

Description :

According to its model number and software versions, the remote host
is a Xerox Document Centre device with an embedded web server that
suffers from multiple flaws, including authentication bypass, denial
of service, unauthorized file access, and cross-site scripting. 

See also : 

http://www.xerox.com/downloads/usa/en/c/cert_XRX05_008.pdf
http://www.xerox.com/downloads/usa/en/c/cert_XRX05_009.pdf

Solution : 

Apply the P24 or P25 patches as described in the Xerox security bulletins. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Xerox MicroServer web server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("xerox_document_centre_detect.nasl");

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
device = get_kb_item("www/document_centre");
if (device) {
  matches = eregmatch(string:device, pattern:"^(.+), ESS (.*)$");
  if (isnull(matches)) exit(0);

  model = matches[1];
  ess = matches[2];

  # No need to check further if ESS ends with ".P24" or ".P25" since that
  # indicates the patch has already been applied.
  if (ess =~ "\.P2[45][^0-9]?") exit(0);

  # Test model number and ESS level against those in Xerox's
  # Security Bulletins XRX05-008 and XRX05-009.
  if (
    # nb: models 535/545/555 with ESS 14.52.000 - 27.18.029.
    (model =~ "^5[345]5" && ver_inrange(ver:ess, low:"14.52.000", high:"27.18.029")) ||

    # nb: models 460/470/480/490 with ESS 19.05.026 - 19.05.528 or 19.5.902 - 19.05.912.
    (
      model =~ "^4[6-9]0" &&
      (
        ver_inrange(ver:ess, low:"19.05.026", high:"19.05.528") ||
        ver_inrange(ver:ess, low:"19.5.902", high:"19.05.912")
      )
    ) ||

    # nb: models 420/426/432/440 with ESS 2.1.2 - 2.3.25.
    (model =~ "^4(20|26|32|40)" && ver_inrange(ver:ess, low:"2.1.2", high:"2.3.25")) ||

    # nb: models 425/432/440 with ESS 3.0.5.4 - 3.2.40.
    (model =~ "^4(25|32|40)" && ver_inrange(ver:ess, low:"3.0.5.4", high:"3.2.40")) ||

    # nb: model 430 with ESS 3.3.24 - 3.3.38.
    (model =~ "^430" && ver_inrange(ver:ess, low:"3.3.24", high:"3.3.38")) ||

    # nb: models 220/230/332/340 with ESS 1.12.08 - 1.12.85.
    (model =~ "^(220|230|332|340)" && ver_inrange(ver:ess, low:"1.12.08", high:"1.12.85"))
  ) security_hole(0);
}
