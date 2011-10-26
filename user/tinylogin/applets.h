/*
 * applets.h - a listing of all tinylogin applets.
 *
 * If you write a new applet, you need to add an entry to this list to make
 * busybox aware of it.
 *
 * It is CRUCIAL that this listing be kept in ascii order, otherwise the binary
 * search lookup contributed by Gaute B Strokkenes stops working. If you value
 * your kneecaps, you'll be sure to *make sure* that any changes made to this
 * file result in the listing remaining in ascii order. You have been warned.
 */

#if defined(PROTOTYPES)
#define APPLET(a,b,c,d,e) \
	extern int b(int argc, char **argv); \
	extern const char e[];
#define APPLET_NOUSAGE(a,b,c,d) \
	extern int b(int argc, char **argv);
#elif defined(MAKE_LINKS)
#define APPLET(a,b,c,d,e) LINK c a
#define APPLET_NOUSAGE(a,b,c,d) LINK c a
#else
const struct Applet applets[] = {
#define APPLET(a,b,c,d,e) {a,b,c,d,e},
#define APPLET_NOUSAGE(a,b,c,d) {a,b,c,d,NULL},
#endif

	APPLET_NOUSAGE("tinylogin", tinylogin_main, _TLG_DIR_BIN, TRUE)
#ifdef TLG_ADDGROUP
	APPLET("addgroup", addgroup_main, _TLG_DIR_BIN, FALSE, addgroup_usage)
#endif
#ifdef TLG_ADDUSER
	APPLET("adduser", adduser_main, _TLG_DIR_BIN, FALSE, adduser_usage)
#endif
#ifdef TLG_DELGROUP
	APPLET("delgroup", delgroup_main, _TLG_DIR_BIN, FALSE, delgroup_usage)
#endif
#ifdef TLG_DELUSER
	APPLET("deluser", deluser_main, _TLG_DIR_BIN, FALSE, deluser_usage)
#endif
#ifdef TLG_GETTY
	APPLET("getty", getty_main, _TLG_DIR_SBIN, FALSE, getty_usage)
#endif
#ifdef TLG_LOGIN
	APPLET("login", login_main, _TLG_DIR_BIN, FALSE, login_usage)
#endif
#ifdef TLG_PASSWD
	APPLET("passwd", passwd_main, _TLG_DIR_USR_BIN, TRUE, passwd_usage)
#endif
#ifdef TLG_SU
	APPLET("su", su_main, _TLG_DIR_BIN, TRUE, su_usage)
#endif
#ifdef TLG_SULOGIN
	APPLET("sulogin", sulogin_main, _TLG_DIR_SBIN, FALSE, sulogin_usage)
#endif
#ifdef TLG_VLOCK
	APPLET("vlock", vlock_main, _TLG_DIR_USR_BIN, TRUE, vlock_usage)
#endif
#if !defined(PROTOTYPES) && !defined(MAKE_LINKS)
	{0, NULL, 0, 0, NULL}
};

/* The -1 arises because of the {0,NULL,0,NULL} entry above. */
size_t NUM_APPLETS = (sizeof(applets) / sizeof(struct Applet) - 1);

#endif
