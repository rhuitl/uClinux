#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20077);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-3184", "CAN-2005-3241", "CAN-2005-3242", "CAN-2005-3243", "CAN-2005-3244", "CAN-2005-3245", "CAN-2005-3246", "CAN-2005-3247", "CAN-2005-3248", "CAN-2005-3249");
 
 name["english"] = "Fedora Core 4 2005-1011: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1011 (ethereal).

Ethereal is a network traffic analyzer for Unix-ish operating systems.

This package lays base for libpcap, a packet capture and filtering
library, contains command-line utilities, contains plugins and
documentation for ethereal. A graphical user interface is packaged
separately to GTK+ package.

Update Information:

Ethereal 0.10.13 fixes the following issues:

The ISAKMP dissector could exhaust system memory.
(CAN-2005-3241)
Fixed in: r15163
Bug IDs: none
Versions affected: 0.10.11 to 0.10.12.

The FC-FCS dissector could exhaust system memory.
(CAN-2005-3241)
Fixed in: r15204
Bug IDs: 312
Versions affected: 0.9.0 to 0.10.12.

The RSVP dissector could exhaust system memory.
(CAN-2005-3241)
Fixed in: r15206, r15600
Bug IDs: 311, 314, 382
Versions affected: 0.9.4 to 0.10.12.

The ISIS LSP dissector could exhaust system memory.
(CAN-2005-3241)
Fixed in: r15245
Bug IDs: 320, 326
Versions affected: 0.8.18 to 0.10.12.

The IrDA dissector could crash. (CAN-2005-3242)
Fixed in: r15265, r15267
Bug IDs: 328, 329, 330, 334, 335, 336
Versions affected: 0.10.0 to 0.10.12.

The SLIMP3 dissector could overflow a buffer. (CAN-2005-3243)
Fixed in: r15279
Bug IDs: 327
Versions affected: 0.9.1 to 0.10.12.

The BER dissector was susceptible to an infinite loop.
(CAN-2005-3244)
Fixed in: r15292
Bug IDs: none
Versions affected: 0.10.3 to 0.10.12.

The SCSI dissector could dereference a null pointer and
crash. (CAN-2005-3246)
Fixed in: r15289
Bug IDs: none
Versions affected: 0.10.3 to 0.10.12.

If the 'Dissect unknown RPC program numbers' option was
enabled,
the ONC RPC dissector might be able to exhaust system memory.
This option is disabled by default. (CAN-2005-3245)
Fixed in: r15290
Bug IDs: none
Versions affected: 0.7.7 to 0.10.12.

The sFlow dissector could dereference a null pointer and
crash (CAN-2005-3246)
Fixed in: r15375
Bug IDs: 356
Versions affected: 0.9.14 to 0.10.12.

The RTnet dissector could dereference a null pointer and
crash (CAN-2005-3246)
Fixed in: r15673
Bug IDs: none
Versions affected: 0.10.8 to 0.10.12.

The SigComp UDVM could go into an infinite loop or crash.
(CAN-2005-3247)
Fixed in: r15715, r15901, r15919
Bug IDs: none
Versions affected: 0.10.12.

If SMB transaction payload reassembly is enabled the SMB
dissector could crash. This preference is disabled by
default. (CAN-2005-3242)
Fixed in: r15789
Bug IDs: 421
Versions affected: 0.9.7 to 0.10.12.

The X11 dissector could attempt to divide by zero.
(CAN-2005-3248)
Fixed in: r15927
Bug IDs: none
Versions affected: 0.10.1 to 0.10.12.

The AgentX dissector could overflow a buffer. (CAN-2005-3243)
Fixed in: r16003
Bug IDs: none
Versions affected: 0.10.10 to 0.10.12.

The WSP dissector could free an invalid pointer.
(CAN-2005-3249)
Fixed in: r16220
Bug IDs: none
Versions affected: 0.10.1 to 0.10.12.

iDEFENSE found a buffer overflow in the SRVLOC dissector.
(CAN-2005-3184)
Fixed in: r16206
Bug IDs: none
Versions affected: 0.10.0 to 0.10.12.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ethereal-0.10.13-1.FC4.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.13-1.FC4.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"ethereal-", release:"FC4") )
{
 set_kb_item(name:"CAN-2005-3184", value:TRUE);
 set_kb_item(name:"CAN-2005-3241", value:TRUE);
 set_kb_item(name:"CAN-2005-3242", value:TRUE);
 set_kb_item(name:"CAN-2005-3243", value:TRUE);
 set_kb_item(name:"CAN-2005-3244", value:TRUE);
 set_kb_item(name:"CAN-2005-3245", value:TRUE);
 set_kb_item(name:"CAN-2005-3246", value:TRUE);
 set_kb_item(name:"CAN-2005-3247", value:TRUE);
 set_kb_item(name:"CAN-2005-3248", value:TRUE);
 set_kb_item(name:"CAN-2005-3249", value:TRUE);
}
