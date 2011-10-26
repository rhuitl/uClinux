#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20136);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2753", "CVE-2005-2754", "CVE-2005-2755", "CVE-2005-2756");
 script_bugtraq_id(15306, 15307, 15308, 15309);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"20475");
   script_xref(name:"OSVDB", value:"20476");
   script_xref(name:"OSVDB", value:"20477");
   script_xref(name:"OSVDB", value:"20478");
 }
 name["english"] = "Quicktime < 7.0.3 (Windows)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote version of QuickTime may allow an attacker to execute
arbitrary code on the remote host. 

Description :

The remote Windows host is running a version of Quicktime that is
older than Quicktime 7.0.3. 

The remote version of this software is reportedly vulnerable to
various buffer overflows that may allow an attacker to execute
arbitrary code on the remote host by sending a malformed file to a
victim and have him open it using QuickTime player. 

See also : 

http://docs.info.apple.com/article.html?artnum=302772

Solution : 

Upgrade to Quicktime 7.0.3 or later.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Quicktime < 7.0.3";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("quicktime_installed.nasl");
 script_require_keys("SMB/QuickTime/Version");

 exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (ver && ver =~ "^([0-6]\.|7\.0\.[0-2])") security_warning(get_kb_item("SMB/transport"));
