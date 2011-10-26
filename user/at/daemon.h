void daemon_setup(void);
void daemon_cleanup(void);

void
#ifdef HAVE_ATTRIBUTE_NORETURN
__attribute__((noreturn))
#endif
pabort (const char *fmt, ...);

void
#ifdef HAVE_ATTRIBUTE_NORETURN
__attribute__((noreturn))
#endif
perr (const char *fmt, ...);

extern int daemon_debug;
