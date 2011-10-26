# 
# (C) 2005 Tenable Network Security
#

if(description)
{
 script_id(19762);
 script_version ("$Revision: 1.5 $");
 name["english"] = "SNMP settings";

 desc["english"] = "
Synopsis :

Set SNMP settings.

Description :

This script just sets global variables (SNMP community string
and SNMP port) and does not perform any security check.

Solution : 

None

Risk factor : 

None";

 script_description(english:desc["english"]);
 script_name(english:name["english"]);
 family["english"] = "Settings";
 script_family(english:family["english"]);
 
 summary["english"] = "set SNMP settings";
 script_summary(english:summary["english"]);
 script_copyright(english:"Copyright (C) 2005 Tenable Network Security");
 script_category(ACT_GATHER_INFO);
 
 script_add_preference(name: "Community name :", type: "entry", value: "public");
 script_add_preference(name: "UDP port :", type: "entry", value: "161");

 exit(0);
}

include ("snmp_func.inc");

community = script_get_preference("Community name :");
port = script_get_preference("UDP port :");
if (!port) 
  port = 161;

if (isnull(community))
  community = "public";

soc = open_sock_udp (port);
if ( ! soc ) exit(0);
index = snmp_request_next (socket:soc, community:community, oid:"1.3", timeout:2);
close(soc);
if (isnull(index))
{
 SNMP_VERSION = 1; # SNMPv2
 soc = open_sock_udp (port);
 if ( ! soc ) exit(0);
 index = snmp_request_next (socket:soc, community:community, oid:"1.3", timeout:2);
 close(soc);
 if (isnull(index))
   exit (0);
}

set_kb_item(name:"SNMP/community", value:community);
set_kb_item(name:"SNMP/port", value:port);
set_kb_item(name:"SNMP/version", value:SNMP_VERSION);
