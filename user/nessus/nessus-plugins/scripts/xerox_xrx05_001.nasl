#
# (C) Tenable Network Security
#


if (description) {
  script_id(18266);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(12335);

  name["english"] = "Xerox DocuCentre / WorkCentre Postscript Directory Traversal Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is prone to a directory traversal attack. 

Description :

According to its model number and software versions, the remote host
is a Xerox Document Centre or WorkCentre device in which the
PostScript interpreter may allow unauthorized access to the underlying
directory structure.  Using a specially crafted PostScript file, an
attacker can exploit this flaw and gain access to sensitive files on
the affected device, including its encrypted password file. 

See also : 

http://www.xerox.com/downloads/usa/en/c/CERT_Xerox_Security_XRX05_001.pdf
http://www.xerox.com/downloads/usa/en/c/CERT_Xerox_Security_XRX04-10.pdf
http://www.xerox.com/downloads/usa/en/c/CERT_Xerox_Security_XRX04-05.pdf
http://www.xerox.com/downloads/usa/en/c/CERT_Xerox_Security_XRX04-03.pdf

Solution : 

Apply the appropriate patches as described in the Xerox security
bulletins. 

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:L/Au:NR/C:C/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks model number / software version of Xerox DocuCentre and WorkCentre devices";
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

  # No need to check further if ESS has ".P9" or ".P12" since these
  # indicate the patch has already been applied.
  if (ess =~ "\.P(9|12)[^0-9]?") exit(0);

  # Test model number and ESS level against those in Xerox's
  # Security Bulletin XRX04-005.
  if (
    # nb: models 535/545/555 with ESS 19.10.047.1 - 19.12.19.1
    (model =~ "5[345]5" && ver_inrange(ver:ess, low:"19.10.047.1", high:"19.12.19.1")) ||

    # nb: models 460/470/480/490 with ESS <= 19.05.519 or 19.5.902 - 19.5.912.
    (
      model =~ "4[6-9]0" &&
      (
        ver_inrange(ver:ess, low:"0", high:"19.05.519") ||
        ver_inrange(ver:ess, low:"19.5.902", high:"19.5.912")
      )
    ) ||

    # nb: models 420/432/440 with ESS 2.1.2 - 2.3.19
    (model =~ "4(20|32|40)" && ver_inrange(ver:ess, low:"2.1.2", high:"2.3.19")) ||

    # nb: models 425/432/440 with ESS 3.0.5.4 - 3.2.29
    (model =~ "4(25|32|40)" && ver_inrange(ver:ess, low:"3.0.5.4", high:"3.2.29")) ||

    # nb: model 430 with ESS 3.3.24 - 3.3.29
    (model =~ "430" && ver_inrange(ver:ess, low:"3.3.24", high:"3.3.29")) ||

    # nb: models 240/255/265 with ESS 17.4.10 - 17.9.34 or 18.6.05 - 18.6.96
    (
      model =~ "2(40|55|65)" && 
      (
        # nb: there's no patch for 17.4.10 - 17.9.34.
        ver_inrange(ver:ess, low:"17.4.10", high:"17.9.34") ||
        ver_inrange(ver:ess, low:"18.6.05", high:"18.6.96")
      )
    ) ||

    # nb: models 220/230/332/340 with ESS 1.12.08 - 1.12.85
    (model =~ "(2[23]0|3(32|40))" && ver_inrange(ver:ess, low:"1.12.08", high:"1.12.85"))
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

  # No need to check further if ESS has ".P5", ".P18", or ".P19" since
  # these indicate the patch has already been applied.
  if (ess =~ "\.P(5|18|19)[^0-9]?") exit(0);

  # Test model number and software version against those in Xerox's 
  # Security Bulletins XRX04-003, XRX04-010, and XRX05-001.
  if (
    # nb: models M35/M45/M55 or Pro 35/45/55 with ESS 1.01.108.1 - 1.02.358.3 or SCD 2.28.11.000 - 4.97.20.025
    (
      model =~ "(M|Pro )[345]5" && 
      (
        ver_inrange(ver:ess, low:"1.01.108.1", high:"1.02.358.3") ||
        ver_inrange(ver:scd, low:"2.28.11.000", high:"4.97.20.025")
      )
    ) ||

    # nb: models 65/75/90 with ESS 1.00.60.3 - 1.02.055.2 or SCD 01.001.00.060 - 01.001.02.082
    (
      model =~ "(65|75|90)" && 
      (
        ver_inrange(ver:ess, low:"1.00.60.3", high:"1.02.055.2") ||
        ver_inrange(ver:scd, low:"01.001.00.060", high:"01.001.02.082")
      )
    ) ||

    # nb: models 32/40 Color with ESS 01.00.060 - 01.02.058.4
    (model =~ "(32|40)C" && ver_inrange(ver:ess, low:"01.00.060", high:"01.02.058.4")) ||

    # nb: models Pro 32/40 Color with SCD 01.00.060 - 01.02.083
    (model =~ "Pro (32|40)C" && ver_inrange(ver:scd, low:"01.00.060", high:"01.02.083"))
  ) security_note(0);
}
