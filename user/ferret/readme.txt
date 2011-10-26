Copyright (c) 2007 by Errata Security

FERRET - a broadcast analysis tool

This tool is designed to demonstrate the problem of "data seapage".
The average machine broadcasts a lot of information about itself
on open networks. This tool captures and organizes this information.

This code is extremely low quality, hacked together in order to
demonstrate the problem at the BlackHat Federal 2007 conference.
Higher quality code should be available around May 2007 on our
website at http://www.erratasec.com.

To build this for Windows, you need the WinPcap developer kit.
This code should compile on other platforms, such as Linux, Solaris,
MacOS, and other platforms with libpcap.

To run it live:
 ferret -i1
where '1' is interface #1.

To run from capture files:
 ferret foo.pcap bar.pcap


Author: Robert Graham <robert_david_graham@yahoo.com>

