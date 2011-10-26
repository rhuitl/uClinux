#
# (C) Tenable Network Security
#



if(description)
{
 script_id(11559);
# script_cve_id("CVE-MAP-NOMATCH");
 script_version ("$Revision: 1.4 $");
 desc["english"] = "
The remote host is a WSP100 802.11b Remote Sensor from 
Network Chemistry.

This device sniffs data flowing on the channels used
by 802.11b and forwards it to any host which 'subscribes'
to this device.

An attacker may use this device to sniff 802.11b networks 
of the area it is deployed from across the planet.

Solution : filter incoming traffic to this host and make sure only
authorized hosts can connect to it.

Risk factor : Medium";

 name["english"] = "Network Chemistry Wireless Sensor Detection";
 script_name(english:name["english"]);


 script_description(english:desc["english"]);

 script_summary(english:"Detects Wireless Sensor");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("snmp_sysDesc.nasl");
 exit(0);
}

#
# The script code starts here
#
mydata = get_kb_item("SNMP/sysDesc");
if(!mydata) exit(0);
if("802.11b Remote Sensor" >< mydata)security_warning(port);
