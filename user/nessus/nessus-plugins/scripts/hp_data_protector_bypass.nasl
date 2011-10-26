#
# (C) Tenable Network Security
#

  desc["english"] = "
Synopsis :

It is possible to execute code on the remote host through the backup
agent.

Description :

The remote version of HP OpenView Data Protector is vulnerable to an
authentication bypass vulnerability. By sending specially crafted
requests to the remote host, an attacker may be able to execute
unauthorized Backup commands.
Due to the nature of the software, a successful exploitation of this
vulnerability could result in remote code execution.

See also : 

http://www.niscc.gov.uk/niscc/docs/br-20060811-00550.html

Solution :

If this service is not needed, disable it or filter incoming traffic
to this port.
HP has released a set of patches for Data Protector 5.10 and 5.50:

http://itrc.hp.com/service/cki/docDisplay.do?docId=c00742778

Risk factor : 

None";

  
if (description) {
  script_id(22225);
  script_cve_id("CVE-2006-4201");
  script_bugtraq_id(19495);
  script_version("$Revision: 1.2 $");

  name["english"] = "HP OpenView Storage Data Protector Backup Agent Remote Arbitrary Command Execution Vulnerability";
  script_name(english:name["english"]);
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Data Protector version";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
  script_require_ports(5555);
  script_dependencies ("hp_data_protector_installed.nasl");
  script_require_keys ("Services/data_protector/version", "Services/data_protector/build");
  exit(0);
}

version = get_kb_item ("Services/data_protector/version");
build = get_kb_item ("Services/data_protector/build");

port = 5555;

if (!version || !build)
  exit (0);

if ((version == "unknown") || (build == "unknown"))
  exit (0);

vulnerable = FALSE;

if (version == "A.05.50")
{
 # unpatched version == build number
 if (egrep (pattern:"^[0-9]+", string:build))
   vulnerable = TRUE;

 # windows patch name (last vulnerable = DPWIN_00202)
 else if (egrep (pattern:"DPWIN_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"DPWIN_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build <= 202)
    vulnerable = TRUE;
 }
 # windows security patch (fixed in SSPNT550_110)
 else if (egrep (pattern:"SSPNT550_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPNT550_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 110)
    vulnerable = TRUE;
 }
 # solaris security patch (fixed in SSPSOL550_035)
 else if (egrep (pattern:"SSPSOL550_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPSOL550_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 35)
    vulnerable = TRUE;
 }
 # hp-ux security patch (fixed in SSPUX550_124)
 else if (egrep (pattern:"SSPUX550_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPUX550_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 124)
    vulnerable = TRUE;
 }
}
else if (version == "A.05.10")
{
 # unpatched version == build number
 if (egrep (pattern:"^[0-9]+", string:build))
   vulnerable = TRUE;

 # windows patch name (last vulnerable = DPWIN_00172)
 if (egrep (pattern:"DPWIN_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"DPWIN_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build <= 172)
    vulnerable = TRUE;
 }
 # windows security patch (fixed in SSPNT510_080)
 else if (egrep (pattern:"SSPNT550_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPNT550_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 80)
    vulnerable = TRUE;
 }
 # solaris security patch (fixed in SSPSOL510_018)
 else if (egrep (pattern:"SSPSOL510_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPSOL510_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 18)
    vulnerable = TRUE;
 }
 # hp-ux security patch (fixed in SSPUX510_94)
 else if (egrep (pattern:"SSPUX510_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPUX510_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 94)
    vulnerable = TRUE;
 }
}

if (vulnerable)
  security_hole (port:port);
