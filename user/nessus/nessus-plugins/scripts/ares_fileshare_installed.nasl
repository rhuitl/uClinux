#
# (C) Tenable Network Security
#


if (description) {
  script_id(19386);
  script_version("$Revision: 1.2 $");

  name["english"] = "Ares Fileshare Detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote Windows host contains a peer-to-peer filesharing
application. 

Description :

Ares Fileshare is installed on the remote host.  Ares Fileshare is a
P2P application that supports connecting to several P2P networks; eg,
Gnutella and OpenFT.  As such, it may not be suitable for use in a
business environment. 

In addition, note that it's not possible for Nessus to determine the
installed version of Ares Fileshare and that some versions suffer from
remotely exploitable vulnerabilities; eg, Bugtraq 14377.

See also : 

http://www.aresfileshare.com/

Solution :

Make sure use of this program is in accordance with your corporate
security policy. 

Risk factor :

None";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects Ares Fileshare";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for evidence of Ares Fileshare.
key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Ares Fileshare/DisplayName";
if (get_kb_item(key)) security_note(port);

