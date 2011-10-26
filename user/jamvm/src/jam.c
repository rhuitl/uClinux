/*
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008
 * Robert Lougher <rob@lougher.org.uk>.
 *
 * This file is part of JamVM.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "jam.h"
#include "class.h"
#include "symbol.h"

#ifdef USE_ZIP
#define BCP_MESSAGE "<jar/zip files and directories separated by :>"
#else
#define BCP_MESSAGE "<directories separated by :>"
#endif

void showNonStandardOptions() {
    printf("  -Xbootclasspath:%s\n", BCP_MESSAGE);
    printf("\t\t   locations where to find the system classes\n");
    printf("  -Xbootclasspath/a:%s\n", BCP_MESSAGE);
    printf("\t\t   locations are appended to the bootstrap class path\n");
    printf("  -Xbootclasspath/p:%s\n", BCP_MESSAGE);
    printf("\t\t   locations are prepended to the bootstrap class path\n");
    printf("  -Xbootclasspath/c:%s\n", BCP_MESSAGE);
    printf("\t\t   locations where to find Classpath's classes\n");
    printf("  -Xbootclasspath/v:%s\n", BCP_MESSAGE);
    printf("\t\t   locations where to find JamVM's classes\n");
    printf("  -Xnoasyncgc\t   turn off asynchronous garbage collection\n");
    printf("  -Xcompactalways  always compact the heap when garbage-collecting\n");
    printf("  -Xnocompact\t   turn off heap-compaction\n");
#ifdef INLINING
    printf("  -Xnoinlining\t   turn off interpreter inlining\n");
    printf("  -Xshowreloc\t   show opcode relocatability\n");
    printf("  -Xreplication:[none|always|<value>]\n");
    printf("\t\t   none : always re-use super-instructions\n");
    printf("\t\t   always : never re-use super-instructions\n");
    printf("\t\t   <value> copy when usage reaches threshold value\n");
    printf("  -Xcodemem:[unlimited|<size>] (default maximum heapsize/4)\n");
#endif
    printf("  -Xms<size>\t   set the initial size of the heap (default = %dM)\n", DEFAULT_MIN_HEAP/MB);
    printf("  -Xmx<size>\t   set the maximum size of the heap (default = %dM)\n", DEFAULT_MAX_HEAP/MB);
    printf("  -Xss<size>\t   set the Java stack size for each thread (default = %dK)\n", DEFAULT_STACK/KB);
    printf("\t\t   size may be followed by K,k or M,m (e.g. 2M)\n");
}

void showUsage(char *name) {
    printf("Usage: %s [-options] class [arg1 arg2 ...]\n", name);
    printf("                 (to run a class file)\n");
    printf("   or  %s [-options] -jar jarfile [arg1 arg2 ...]\n", name);
    printf("                 (to run a standalone jar file)\n");
    printf("\nwhere options include:\n");
    printf("  -help\t\t   print out this message\n");
    printf("  -version\t   print out version number and copyright information\n");
    printf("  -showversion     show version number and copyright and continue\n");
    printf("  -fullversion     show jpackage-compatible version number and exit\n");
    printf("  -cp -classpath   <jar/zip files and directories separated by :>\n");
    printf("\t\t   locations where to find application classes\n");
    printf("  -verbose[:class|gc|jni]\n");
    printf("\t\t   :class print out information about class loading, etc.\n");
    printf("\t\t   :gc print out results of garbage collection\n");
    printf("\t\t   :jni print out native method dynamic resolution\n");
    printf("  -D<name>=<value> set a system property\n");
    printf("  -X\t\t   show help on non-standard options\n");
}

void showVersionAndCopyright() {
    printf("java version \"%s\"\n", JAVA_COMPAT_VERSION);
    printf("JamVM version %s\n", VERSION);
    printf("Copyright (C) 2003-2008 Robert Lougher <rob@lougher.org.uk>\n\n");
    printf("This program is free software; you can redistribute it and/or\n");
    printf("modify it under the terms of the GNU General Public License\n");
    printf("as published by the Free Software Foundation; either version 2,\n");
    printf("or (at your option) any later version.\n\n");
    printf("This program is distributed in the hope that it will be useful,\n");
    printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
    printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
    printf("GNU General Public License for more details.\n");

    printf("\nBuild information:\n\nExecution Engine: ");

#ifdef THREADED
#ifdef DIRECT
#ifdef INLINING
    printf("inline-");
#else /* INLINING */
    printf("direct-");
#endif /* INLINING */
#endif /* DIRECT */
    printf("threaded interpreter");
#ifdef USE_CACHE
    printf(" with stack-caching\n");
#else /* USE_CACHE*/
    printf("\n");
#endif /* USE_CACHE */
#else /* THREADED */
    printf("switch-based interpreter\n");
#endif /*THREADED */

#if defined(__GNUC__) && defined(__VERSION__)
    printf("Compiled with: gcc %s\n", __VERSION__);
#endif

    printf("\nBoot Library Path: %s\n", getBootDllPath());
    printf("Boot Class Path: %s\n", DFLT_BCP);
}

void showFullVersion() {
    printf("java full version \"jamvm-%s\"\n", JAVA_COMPAT_VERSION);
}

int parseCommandLine(int argc, char *argv[], InitArgs *args) {
    int is_jar = FALSE;
    int status = 1;
    int i;

    Property props[argc-1];
    int props_count = 0;

    for(i = 1; i < argc; i++) {
        if(*argv[i] != '-') {
            if(args->min_heap > args->max_heap) {
                printf("Minimum heap size greater than max!\n");
                goto exit;
            }

            if((args->props_count = props_count)) {
                args->commandline_props = (Property*)sysMalloc(props_count * sizeof(Property));
                memcpy(args->commandline_props, &props[0], props_count * sizeof(Property));
            }

            if(is_jar) {
                args->classpath = argv[i];
                argv[i] = "jamvm/java/lang/JarLauncher";
            }

            return i;
        }

        if(strcmp(argv[i], "-help") == 0) {
            status = 0;
            break;

        } else if(strcmp(argv[i], "-X") == 0) {
            showNonStandardOptions();
            status = 0;
            goto exit;

        } else if(strcmp(argv[i], "-version") == 0) {
            showVersionAndCopyright();
            status = 0;
            goto exit;

        } else if(strcmp(argv[i], "-showversion") == 0) {
            showVersionAndCopyright();

        } else if(strcmp(argv[i], "-fullversion") == 0) {
            showFullVersion();
            status = 0;
            goto exit;

        } else if(strncmp(argv[i], "-verbose", 8) == 0) {
            char *type = &argv[i][8];

            if(*type == '\0' || strcmp(type, ":class") == 0)
                args->verboseclass = TRUE;

            else if(strcmp(type, ":gc") == 0 || strcmp(type, "gc") == 0)
                args->verbosegc = TRUE;

            else if(strcmp(type, ":jni") == 0)
                args->verbosedll = TRUE;

        } else if(strcmp(argv[i], "-Xnoasyncgc") == 0)
            args->noasyncgc = TRUE;

        else if(strncmp(argv[i], "-ms", 3) == 0 || strncmp(argv[i], "-Xms", 4) == 0) {
            args->min_heap = parseMemValue(argv[i] + (argv[i][1] == 'm' ? 3 : 4));
            if(args->min_heap < MIN_HEAP) {
                printf("Invalid minimum heap size: %s (min %dK)\n", argv[i], MIN_HEAP/KB);
                goto exit;
            }

        } else if(strncmp(argv[i], "-mx", 3) == 0 || strncmp(argv[i], "-Xmx", 4) == 0) {
            args->max_heap = parseMemValue(argv[i] + (argv[i][1] == 'm' ? 3 : 4));
            if(args->max_heap < MIN_HEAP) {
                printf("Invalid maximum heap size: %s (min is %dK)\n", argv[i], MIN_HEAP/KB);
                goto exit;
            }

        } else if(strncmp(argv[i], "-ss", 3) == 0 || strncmp(argv[i], "-Xss", 4) == 0) {
            args->java_stack = parseMemValue(argv[i] + (argv[i][1] == 's' ? 3 : 4));
            if(args->java_stack < MIN_STACK) {
                printf("Invalid Java stack size: %s (min is %dK)\n", argv[i], MIN_STACK/KB);
                goto exit;
            }

        } else if(strncmp(argv[i], "-D", 2) == 0) {
            char *pntr, *key = strcpy(sysMalloc(strlen(argv[i]+2) + 1), argv[i]+2);
            for(pntr = key; *pntr && (*pntr != '='); pntr++);
            if(*pntr)
                *pntr++ = '\0';
            props[props_count].key = key;
            props[props_count++].value = pntr;

        } else if(strcmp(argv[i], "-classpath") == 0 || strcmp(argv[i], "-cp") == 0) {

            if(i == (argc-1)) {
                printf("%s : missing path list\n", argv[i]);
                goto exit;
            }
            args->classpath = argv[++i];

        } else if(strncmp(argv[i], "-Xbootclasspath:", 16) == 0) {

            args->bootpathopt = '\0';
            args->bootpath = argv[i] + 16;

        } else if(strncmp(argv[i], "-Xbootclasspath/a:", 18) == 0 ||
                  strncmp(argv[i], "-Xbootclasspath/p:", 18) == 0 ||
                  strncmp(argv[i], "-Xbootclasspath/c:", 18) == 0 ||
                  strncmp(argv[i], "-Xbootclasspath/v:", 18) == 0) {

            args->bootpathopt = argv[i][16];
            args->bootpath = argv[i] + 18;

        } else if(strcmp(argv[i], "-jar") == 0) {
            is_jar = TRUE;

        } else if(strcmp(argv[i], "-Xnocompact") == 0) {
            args->compact_specified = TRUE;
            args->do_compact = FALSE;

        } else if(strcmp(argv[i], "-Xcompactalways") == 0) {
            args->compact_specified = args->do_compact = TRUE;
#ifdef INLINING
        } else if(strcmp(argv[i], "-Xnoinlining") == 0) {
            /* Turning inlining off is equivalent to setting
               code memory to zero */
            args->codemem = 0;

        } else if(strncmp(argv[i], "-Xreplication:", 14) == 0) {
            char *pntr = argv[i] + 14;

            if(strcmp(pntr, "none") == 0)
                args->replication = INT_MAX;
            else
                if(strcmp(pntr, "always") == 0)
                    args->replication = 0;
                else
                    args->replication = strtol(pntr, NULL, 0);

        } else if(strncmp(argv[i], "-Xcodemem:", 10) == 0) {
            char *pntr = argv[i] + 10;

            args->codemem = strncmp(pntr, "unlimited", 10) == 0 ?
                INT_MAX : parseMemValue(pntr);

        } else if(strcmp(argv[i], "-Xshowreloc") == 0) {
            showRelocatability();
            status = 0;
            goto exit;
#endif
        } else {
            printf("Unrecognised command line option: %s\n", argv[i]);
            break;
        }
    }

    showUsage(argv[0]);

exit:
    exit(status);
}

int main(int argc, char *argv[]) {
    Class *array_class, *main_class;
    Object *system_loader, *array;
    MethodBlock *mb;
    InitArgs args;
    int class_arg;
    char *cpntr;
    int status;
    int i;

    setDefaultInitArgs(&args);
    class_arg = parseCommandLine(argc, argv, &args);

    args.main_stack_base = &array_class;
    initVM(&args);

   if((system_loader = getSystemClassLoader()) == NULL) {
        printf("Cannot create system class loader\n");
        printException();
        exitVM(1);
    }

    mainThreadSetContextClassLoader(system_loader);

    for(cpntr = argv[class_arg]; *cpntr; cpntr++)
        if(*cpntr == '.')
            *cpntr = '/';

    if((main_class = findClassFromClassLoader(argv[class_arg], system_loader)) != NULL)
        initClass(main_class);

    if(exceptionOccurred()) {
        printException();
        exitVM(1);
    }

    mb = lookupMethod(main_class, SYMBOL(main), SYMBOL(_array_java_lang_String__V));
    if(!mb || !(mb->access_flags & ACC_STATIC)) {
        printf("Static method \"main\" not found in %s\n", argv[class_arg]);
        exitVM(1);
    }

    /* Create the String array holding the command line args */

    i = class_arg + 1;
    if((array_class = findArrayClass(SYMBOL(array_java_lang_String))) &&
           (array = allocArray(array_class, argc - i, sizeof(Object*))))  {
        Object **args = (Object**)ARRAY_DATA(array) - i;

        for(; i < argc; i++)
            if(!(args[i] = Cstr2String(argv[i])))
                break;

        /* Call the main method */
        if(i == argc)
            executeStaticMethod(main_class, mb, array);
    }

    /* ExceptionOccurred returns the exception or NULL, which is OK
       for normal conditionals, but not here... */
    if((status = exceptionOccurred() ? 1 : 0))
        printException();

    /* Wait for all but daemon threads to die */
    mainThreadWaitToExitVM();
    exitVM(status);
}
