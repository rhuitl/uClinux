///
///	@file 	test.h
/// @brief 	Header for the Embedded Unit Test Framework (eUnit)
///
///	EUnit provies a framework to create unit tests for C++ code. It is similar
///	in design and philosophy to the Java JUnit framework.
///
////////////////////////////////////////////////////////////////////////////////
//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//	The latest version of this code is available at http://www.mbedthis.com
//
//	This software is open source; you can redistribute it and/or modify it 
//	under the terms of the GNU General Public License as published by the 
//	Free Software Foundation; either version 2 of the License, or (at your 
//	option) any later version.
//
//	This program is distributed WITHOUT ANY WARRANTY; without even the 
//	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
//	See the GNU General Public License for more details at:
//	http://www.mbedthis.com/downloads/gplLicense.html
//	
//	This General Public License does NOT permit incorporating this software 
//	into proprietary programs. If you are unable to comply with the GPL, a 
//	commercial license for this software and support services are available
//	from Mbedthis Software at http://www.mbedthis.com
//
////////////////////////////////////////////////////////////////////////////////

#ifndef _h_TEST
#define _h_TEST 1

/////////////////////////////////// Includes ///////////////////////////////////

#include "mpr.h"

/////////////////////////// Forward Class Declarations /////////////////////////

class	MprTest;
class	MprTestCase;
class	MprTestFailure;
class	MprTestGroup;
class	MprTestResult;
class	MprTestSession;
class	MprTestListener;

/////////////////////////////////// Constants //////////////////////////////////

enum MprTestLevel {
	MPR_BASIC = 0,
	MPR_THOROUGH = 1,
	MPR_DEDICATED = 2,
};

//
//	Max time for select to block waiting for something to happen
//
#define MPR_TEST_POLL_NAP	10
#define MPR_TEST_SLEEP		(60000)

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// MprTestFailure ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MprTestFailure : public MprLink
{
  public:
	MprStr			file;
	int				line;
	MprStr			message;

  public:
					MprTestFailure(char *file, int line, char *message);
					~MprTestFailure();
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MprTestResult ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

#undef  assert
#define assert(C)		assertTrue(this, MPR_L, C, #C)

class MprTestResult
{
  private:
	int				activeThreadCount;		// Currently active test threads
	bool			continueOnFailures;		// Keep testing on failures
	bool			debugOnFailures;		// Break to the debugger
	bool			singleStep;				// Pause between tests
	MprList			failures;				// List of all failures
	MprList			listeners;				// Users registered for output
	int				start;					// When testing began
	MprHashTable	*successes;				// Hash of succeeding tests
	int				testCount;				// Total count of all tests
	int				testFailedCount;		// Total count of failing tests
	int				verbose;				// Output activity trace

#if BLD_FEATURE_MULTITHREAD
	MprMutex		*mutex;					// Multi-thread sync
#endif

  public:
					MprTestResult();
					~MprTestResult();
	void			adjustTestCount(bool success, int i);
	void			adjustThreadCount(int i);
	void			addFailure(MprTestFailure *failure);
	void			addSuccess(MprTest *test);
	void			addListener(MprTestListener *lp);
	bool			assertTrue(MprTest *test, char *file, int line, 
						bool success, char *testCode);
	bool			getContinueOnFailures();
	bool			getDebugOnFailures();
	int				getFailureCount();
	MprList			*getFailureList();
	MprTestFailure*	getFirstFailure();
	MprTestLevel	getLevel();
	int				getListenerCount();
	bool			getSingleStep();
	int				getTestCount();
	int				getThreadCount();
	int				getVerbose();
	int				report();
	void			setContinueOnFailures(bool on);
	void			setDebugOnFailures(bool on);
	void			setSingleStep(bool on);
	void			setVerbosity(int verbose);

#if BLD_FEATURE_MULTITHREAD
	inline void		lock() { mutex->lock(); };
	inline void		unlock() { mutex->unlock(); };
#else
	inline void		lock() { };
	inline void		unlock() { };
#endif
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MprTest ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

typedef void		(MprTest::*MprTestProc)(MprTestResult *result);

class MprTest : public MprLink
{
protected:
	volatile bool	condWakeFlag;			// Used when single-threaded
	volatile bool	cond2WakeFlag;			// Used when single-threaded
	MprTestProc		fn;						// Test function to run (TestCase)
	MprTestLevel	level;					// Level at which test should run
	int				failureCount;			// Total failures of this test
	MprStr			name;					// Name of test
	MprTestSession*	session;				// Pointer to the TestSession
	bool			success;				// Result of last run

#if BLD_FEATURE_MULTITHREAD
	MprCond			*cond;					// Multi-thread sync
	MprCond			*cond2;					// Second multi-thread sync
	MprMutex		*mutex;					// Multi-thread sync
#endif

  public:
					MprTest(const char *name);
	virtual			~MprTest();
	void			adjustFailureCount(int adj);
	int				getFailureCount();
	int				getArgc();
	int				getFirstArg();
	char			**getArgv();
	MprTestLevel	getLevel();
	char			*getName();
	bool			isSuccess();

	void			reset();
	void			signalTest();
	void			signalTest2();
	bool			waitForTest(int timeout);
	bool			waitForTest2(int timeout);

#if BLD_FEATURE_MULTITHREAD
	inline void		lock() { mutex->lock(); };
	inline void		unlock() { mutex->unlock(); };
#else
	inline void		lock() { };
	inline void		unlock() { };
#endif

	virtual int		classInit(MprTestResult *rp);
	virtual void	classTerm(MprTestResult *rp);
	virtual int		init(MprTestResult *rp);
	virtual void	run(MprTestResult *result, int level) = 0;
	virtual void	setSession(MprTestSession *sp);
	virtual void	term(MprTestResult *rp);
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MprTestCase //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MprTestCase : public MprTest
{
  private:
	MprTestGroup	*group;					// Parent group

  public:
					MprTestCase(const char *name, MprTestProc fn, 
						MprTestLevel level);
					~MprTestCase();
	void			run(MprTestResult *result, int level);
	void			setGroup(MprTestGroup *group);
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// MprTestGroup //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

#define ADD_TEST(level, className, functionName) \
	add(#functionName, (MprTestProc) &className::functionName, level);

class MprTestGroup : public MprTest
{
  protected:
	MprTestResult	*result;				// Temporary pointer for threads
	MprList			testList;				// List of tests in this group

  public:
					MprTestGroup(const char *name);
					~MprTestGroup();
	void			add(MprTestGroup *group, MprTestLevel level = MPR_BASIC);
	void			add(char *name, MprTestProc fn, 
						MprTestLevel level = MPR_BASIC);
	MprTestResult	*getResult();
	int				init(MprTestResult *result);
	void			run(MprTestResult *result, int level);
	void			setResult(MprTestResult *rp);
	void			setSession(MprTestSession *sp);
	void			term(MprTestResult *result);
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// MprTestSession /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MprTestSession : public MprTestGroup
{
  private:
	int				argc;					// Count of arguments
	char			**argv;					// Arguments for test
	int				firstArg;				// Count of arguments
	int				iterations;				// Number of times to run the test
	Mpr				*mpr;					// Pointer to Mpr object
	bool			needEventsThread;		// Run a service events thread
	int				numThreads;				// Number of test threads
	int				poolThreads;			// Count of pool threads
	MprTestLevel	sessionLevel;			// Level of entire test
	MprStringList	*testGroups;			// Test groups to run
	int				verbose;				// Output activity trace

  public:
					MprTestSession(char *name);
					~MprTestSession();
	void			cloneSettings(MprTestSession *master);
	int				getArgc();
	char			**getArgv();
	int				getFirstArg();
	int				getIterations();
	Mpr				*getMprp();
	MprTestLevel	getSessionLevel() { return sessionLevel; };
	MprStringList	*getTestGroups() { return testGroups; };
	int				initializeClasses(MprTestResult *rp);
	bool			isRunningEventsThread();
	int				runTests(MprTestResult *rp, Mpr *mpr, int argc, 
						char *argv[], char *switches);
	void			setEventsThread();
	void			terminateClasses(MprTestResult *rp);

	virtual MprTestSession* 
					newSession() = 0;
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////// MprTestListener /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MprTestListener : public MprLink
{
  private:
	MprStr			name;

  public:
					MprTestListener(char *name);
	virtual			~MprTestListener();
	char			*getName();
	virtual void	results(char *fmt, ...);
	virtual void	trace(char *fmt, ...);
};

////////////////////////////////////////////////////////////////////////////////
#endif // _h_TEST 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
