#
# (C) Tenable Network Security
#


if (description) {
  script_id(20958);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2006-0189");
  script_bugtraq_id(16213);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"22348");
  }

  script_name(english:"eStara SoftPhone SDP Data Attribute Buffer Overflow Vulnerability");
  script_summary(english:"Checks version number of eStara SoftPhone");
 
  desc = "
Synopsis :

The remote SIP client is prone to a buffer overflow vulnerability. 

Description :

The version of SoftPhone installed on the remote host reportedly fails
to properly handle SIP packets with long 'a=' lines in the SDP data. 
An unauthenticated remote attacker may be able to exploit this flaw to
overflow a buffer and execute arbitrary code on the remote host. 

See also :

http://www.securityfocus.com/archive/1/archive/1/421596/100/0/threaded

Solution :

Upgrade to eStara SoftPhone version 3.0.1.47 or later. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("estara_softphone_installed.nasl");
  script_require_keys("SMB/SoftPhone/Version");

  exit(0);
}


include("smb_func.inc");


ver = get_kb_item("SMB/SoftPhone/Version");
if (ver) {
  iver = split(ver, sep:'.', keep:FALSE);
  # Check whether it's an affected version.
  if (
    int(iver[0]) < 3 ||
    (
      int(iver[0]) == 3 && 
      int(iver[1]) == 0 &&
      (
        int(iver[2]) < 1 ||
        (int(iver[2]) == 1 && int(iver[3]) < 47)
      )
    )
  ) security_hole(kb_smb_transport());
}
