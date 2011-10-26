#
# (C) Tenable Network Security
#


if (description) {
  script_id(18268);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(12782);

  name["english"] = "Xerox MicroServer Web Server Remote Denial of Service Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is susceptible to a denial of service attack. 

Description :

According to its model number and software versions, the remote host
is a Xerox Document Centre or WorkCentre device with an embedded web
server that is prone to remote denial of service attacks. 
Specifically, memory on the affected device can become corrupted,
triggering a crash and restart, when the web server processes a
malicious URI designed to navigate through various unspecified
directories. 

See also : 

http://www.xerox.com/downloads/usa/en/c/cert_XRX05_004.pdf
http://www.xerox.com/downloads/usa/en/c/CERT_Xerox_Security_XRX04-07.pdf

Solution : 

Apply the P10 or P11 patches as described in the Xerox bulletins.

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for web server remote denial of service vulnerability in Xerox MicroServer";
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

  # No need to check further if ESS ends with ".P11" since that
  # indicates the patch has already been applied.
  if (ess =~ "\.P11") exit(0);

  # Test model number and ESS level against those in Xerox's
  # Security Bulletin XRX05-004.
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

    # nb: models 420/426/432/440 with ESS 2.1.2 - 2.3.21
    (model =~ "4(2[06]|32|40)" && ver_inrange(ver:ess, low:"2.1.2", high:"2.3.21")) ||

    # nb: models 425/432/440 with ESS 3.0.5.4 - 3.2.30
    (model =~ "4(25|32|40)" && ver_inrange(ver:ess, low:"3.0.5.4", high:"3.2.30")) ||

    # nb: model 430 with ESS 3.3.24 - 3.3.30
    (model =~ "430" && ver_inrange(ver:ess, low:"3.3.24", high:"3.3.30"))
  ) security_note(0);
}

# - WorkCentre devices.
device = get_kb_item("www/workcentre");
if (device) {
  matches = eregmatch(string:device, pattern:"^(.+), SCD (.*), ESS (.*)$");
  if (isnull(matches)) exit(0);

  model = matches[1];
  scd = matches[2];
  ess = matches[3];

  # No need to check further if ESS ends with ".P10" since that
  # indicates the patch has already been applied.
  if (ess =~ "\.P10") exit(0);

  # Test model number and software version against those in Xerox's 
  # Security Bulletin XRX04-007.
  if (
    # nb: models M35/M45/M55 or Pro 35/45/55 with ESS 1.01.108.1 - 1.02.372.1
    (model =~ "(M|Pro )[345]5" && ver_inrange(ver:ess, low:"1.01.108.1", high:"1.02.372.1")) ||

    # nb: models 32/40 Color with ESS 01.00.060 - 01.02.072.1
    (model =~ "(32|40)C" && ver_inrange(ver:ess, low:"01.00.060", high:"01.02.072.1"))
  ) security_note(0);
}
