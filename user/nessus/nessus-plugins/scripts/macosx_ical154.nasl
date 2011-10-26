#TRUSTED 6c713ae1c65a18b249e38b52d500228dfdbded99966ce09757c405e6b00e721ddaaa0fd223c74c8cc89c96c9121e9e1f2fe639f28fca503b67bd506e1aadbad7cbde03a74e3abe29a3a8628a3bfd0eaa86b51357f024bd1625795ee8f8003664d048fcb7fd7b2052396001f878435547968cd4e7bc019369d5f97a66c4abb80a6ad902769abcc15bf54306da19bcb48611b7abe6280613c598879666b841da1fe6a36384fda46fce180664216df2fc00b4cd8a6e2c72e06205b0bfc77e3efc939a98ff6ea929395b4ee99c69cb182c76c3d71e48770f24ed6f993d7272c9ba03b631a140dce93a06920b9ac07f0b16329fbfe51267575eac8a539c570facf7d64684d059d825242c0b89dd398ccb6164af29b66c59f465d05d09709428f0ad253b342ce536f897258be6a8cf80eeabed2c15526d4ceaa928c2793ad10e3ee9b94bf85cdcbddf35377500bd3d439c58dcd0b45204067a08d235d907c8501147d93d3ff3151abcaec15eaf1687437657310e9cfda96ccc89c2456dbae424e82804b304ac1be4badf3285073b822f932ef381e9795c9a3867052ad40e184290e69efe1e88c33c90bf5e81a2017fd1b815bcdb2847c6e6f8dd2664ccabaf3417db3d1c3174b1a27ae3ee6f9988dea10d49c0362da67b015707ad7ffeac6a5d03cf5041c391cb0dc4dba904e8c0ca51f1416da0b520257be29024c38a51b294b19415
#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15786);
 script_version ("1.2");
 script_bugtraq_id ( 11728 );
 name["english"] = "iCal 1.5.4";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of iCal which is older than version 1.5.4.

iCal 1.5.4 contains security enhancements to protect the remote computer
when importing events with alarms which open files or application.


Solution : http://www.apple.com/ical/download/
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for iCal 1.5.4";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");
packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  if ( egrep(pattern:"^iCal\.pkg", string:packages) ) 
  {
   if ( egrep(pattern:"^iCal(2[0-9]*|1(5[4-9]|[6-9][0-9]))\.pkg", string:packages) )  exit(0);
  }

  soc = ssh_login_or_reuse_connection();
  if ( ! soc ) exit(0);
  buf = ssh_cmd(socket:soc, cmd:'egrep "<string>1\\.([0-4]\\.|5\\.[0-3])</string>" /Library/Receipts/iCal.pkg/Contents/version.plist');
 if ( buf ) security_hole ( port );
}
