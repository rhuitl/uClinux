#
# (C) Tenable Network Security
#


if (description) {
  script_id(18258);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1936");
  script_bugtraq_id(12783);

  name["english"] = "Xerox MicroServer Unauthorized Access Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is affected by an unauthorized access
vulnerability. 

Description :

According to its model number and software versions, the remote host
is a Xerox Document Centre or WorkCentre device with an embedded web
server that may allow unauthorized access to the web server directory
structure, which in turn may enable a remote attacker to gain access
rights and to make unauthorized changes to the device's system
configuration. 

See also : 

http://www.xerox.com/downloads/usa/en/c/cert_XRX05_003.pdf
http://www.xerox.com/downloads/usa/en/c/CERT_Xerox_Security_XRX04-09.pdf

Solution : 

Apply the P16 or P21 patches as described in the Xerox bulletins.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for authentication bypass vulnerability in Xerox MicroServer";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("xerox_document_centre_detect.nasl", "xerox_workcentre_detect.nasl");

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
#
# - Document Centre devices.
device = get_kb_item("www/document_centre");
if (device) {
  matches = eregmatch(string:device, pattern:"^(.+), ESS (.*)$");
  if (isnull(matches)) exit(0);

  model = matches[1];
  ess = matches[2];

  # No need to check further if ESS ends with ".P16" since that
  # indicates the patch has already been applied.
  if (ess =~ "\.P16[^0-9]?") exit(0);

  # Test model number and ESS level against those in Xerox's
  # Security Bulletin XRX05-003.
  if (
    # nb: models 535/545/555 with ESS <= 27.18.017
    (model =~ "5[345]5" && ver_inrange(ver:ess, low:"0", high:"27.18.017")) ||

    # nb: models 460/470/480/490 with ESS 19.01.037 - 19.05.521 or 19.5.902 - 19.5.912.
    (
      model =~ "4[6-9]0" &&
      (
        ver_inrange(ver:ess, low:"19.01.037", high:"19.05.521") ||
        ver_inrange(ver:ess, low:"19.5.902", high:"19.5.912")
      )
    ) ||

    # nb: models 240/255/265 with ESS 18.01 - 18.6.81.
    (model =~ "2(40|55|65)" && ver_inrange(ver:ess, low:"18.01", high:"18.6.81"))
  ) security_hole(0);
}

# - WorkCentre devices.
device = get_kb_item("www/workcentre");
if (device) {
  matches = eregmatch(string:device, pattern:"^(.+), SCD (.*), ESS (.*)$");
  if (isnull(matches)) exit(0);

  model = matches[1];
  scd = matches[2];
  ess = matches[3];

  # No need to check further if ESS has ".P21" since it
  # indicates the patch has already been applied (except for
  # WorkCentre M35/M45/M55 and M165/M175).
  if (ess =~ "\.P21[^0-9]?") exit(0);

  # Test model number and software versions against those in Xerox's 
  # Security Bulletin XRX04-009.
  if (
    # nb: models M35/M45/M55 with SCD 2.028.11.000 - 2.97.20.032 or 4.84.16.000 - 4.97.20.032.
    (
      model =~ "M[345]5" &&
      (
        ver_inrange(ver:scd, low:"2.028.11.000", high:"2.97.20.032") ||
        ver_inrange(ver:scd, low:"4.84.16.000", high:"4.97.20.032")
      )
    ) ||

    # nb: models Pro 35/45/55 with SCD 3.028.11.000 - 3.97.20.032.
    (model =~ "Pro [345]5" && ver_inrange(ver:scd, low:"3.028.11.000", high:"3.97.20.032")) ||

    # nb: models Pro 65/75/90 with SCD 1.001.00.060 - 1.001.02.084.
    (model =~ "Pro (65|75|90)" && ver_inrange(ver:scd, low:"1.001.00.060", high:"1.001.02.084")) ||

    # nb: models Pro 32/40 Color with SCD 0.001.00.060 - 0.001.02.081.
    (model =~ "Pro (32|40)C" && ver_inrange(ver:scd, low:"0.001.00.060", high:"0.001.02.081"))
  ) security_hole(0);
}
