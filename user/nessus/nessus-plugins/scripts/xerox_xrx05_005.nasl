#
# (C) Tenable Network Security
#


if (description) {
  script_id(18206);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-0703", "CVE-2005-1179");
  script_bugtraq_id(12731, 13196, 13198);
  script_xref(name:"OSVDB", value:"14579");
  script_xref(name:"OSVDB", value:"15747");

  name["english"] = "Xerox MicroServer Unauthorized Access Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote printer suffers from multiple unauthorized access
vulnerabilities. 

Description :

According to its model number and software versions, the remote host
is a Xerox WorkCentre device with an embedded web server with an
unauthenticated account and a weakness in its SNMP authentication. 
These flaws may allow a remote attacker to bypass authentication and
change the device's configuration. 

See also : 

http://www.xerox.com/downloads/usa/en/c/cert_XRX05_005.pdf

Solution : 

Apply the P21 patch as described in the Xerox security bulletin. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for unauthorized access vulnerabilities in Xerox MicroServer";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

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

  # No need to check further if ESS has with ".P21" since that
  # indicates the patch has already been applied (except for 
  # WorkCentre M35/M45/M55 and M165/M175).
  if (ess =~ "\.P21[^0-9]?") exit(0);

  # Test model number and software version against those in Xerox's security bulletin.
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
    (model =~ "Pro (32|40)C" && ver_inrange(ver:scd, low:"0.001.00.060", high:"0.001.02.081")) ||

    # nb: models M165/M175 with SCD 6.47.30.000 - 6.47.33.008 or 8.47.30.000 - 8.47.33.008
    (
      model =~ "M1[67]5" && 
      (
        ver_inrange(ver:scd, low:"6.47.30.000", high:"6.47.33.008") ||
        ver_inrange(ver:scd, low:"8.47.30.000", high:"8.47.33.008")
      )
    ) ||

    # nb: models Pro 165/175 with SCD 7.47.30.000 - 7.47.33.008.
    (model =~ "Pro 1[67]5" && ver_inrange(ver:scd, low:"7.47.30.000", high:"7.47.33.008")) ||

    # nb: models Pro Color 2128/2636/3545 with SCD 0.001.04.044.
    (model =~ "Pro (2128|2636|3545)C" && ver_inrange(ver:scd, low:"0.001.04.044", high:"0.001.04.044"))
  ) security_hole(0);
}
