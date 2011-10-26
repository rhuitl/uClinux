#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: bipin gautam <visitbipin@yahoo.com>
#
#  This script is released under the GNU GPLv2

if(description)
{
 script_id(14726);
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"9761");

 script_version("$Revision: 1.6 $");

 name["english"] = "ZoneAlarm Pro local DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
ZoneAlarm Pro firewall runs on this host.

This version contains a flaw that may allow a local denial of service. To
exploit this flaw, an attacker would need to temper with the files located in
%windir%/Internet Logs. An attacker may modify them and prevent ZoneAlarm
to start up properly.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check ZoneAlarm Pro version";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "Firewalls";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/ZoneAlarm Pro/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/ZoneAlarm Pro/DisplayVersion";

if (get_kb_item (key))
{
 version = get_kb_item (key2);
 if (version)
 {
  set_kb_item (name:"zonealarm/version", value:version);

  if(ereg(pattern:"[1-4]\.|5\.0\.|5\.1\.", string:version))
  {
   security_warning(0);
  }
 }
}
