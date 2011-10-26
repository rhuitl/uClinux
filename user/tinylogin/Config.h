/*
 * This file is parsed by sed. You MUST use single line comments.
 * IE	//#define TLG_BLAH
 */

#define TLG_ADDUSER
#define TLG_ADDGROUP
#define TLG_DELUSER
#define TLG_DELGROUP
#define TLG_LOGIN
#define TLG_SU
//#define TLG_SULOGIN
#define TLG_PASSWD
#define TLG_GETTY
//#define TLG_VLOCK
//
//
//
// This is where feature definitions go.  Generally speaking,
// turning this stuff off makes things a bit smaller (and less 
// pretty/useful).
//
//
// Enable using shadow passwords
#define TLG_FEATURE_SHADOWPASSWDS
//
// Enable checking of /etc/securetty by login
//#define TLG_FEATURE_SECURETTY
//
// Enable using md5 passwords
//#define TLG_FEATURE_MD5_PASSWORDS
//
// Enable using sha passwords
//#define TLG_FEATURE_SHA1_PASSWORDS
//
// This compiles out everything but the most 
// trivial --help usage information (i.e. reduces binary size)
//#define TLG_FEATURE_TRIVIAL_HELP
//
// Enable 'tinylogin --install [-s]' to allow tinylogin
// to create links (or symlinks) at runtime for all the 
// commands that are compiled into the binary.  This needs 
// the /proc filesystem to work properly...
//#define TLG_FEATURE_INSTALLER
//
//
//---------------------------------------------------
// Nothing beyond this point should ever be touched by 
// mere mortals so leave this stuff alone.
//
#ifdef TLG_FEATURE_MD5_PASSWORDS
	#define TLG_MD5
#endif
//
#ifdef TLG_FEATURE_SHA1_PASSWORDS
	#define TLG_SHA1
#endif
