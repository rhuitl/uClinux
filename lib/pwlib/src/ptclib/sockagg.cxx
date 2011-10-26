/*
 * sockagg.cxx
 *
 * Generalised Socket Aggregation functions
 *
 * Portable Windows Library
 *
 * Copyright (C) 2005 Post Increment
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * The Original Code is Portable Windows Library.
 *
 * The Initial Developer of the Original Code is Post Increment
 *
 * Portions of this code were written with the financial assistance of 
 * Metreos Corporation (http://www.metros.com).
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: sockagg.cxx,v $
 * Revision 1.6  2006/01/05 11:39:32  rjongbloed
 * Fixed DevStudio warning
 *
 * Revision 1.5  2006/01/03 04:23:32  csoutheren
 * Fixed Unix implementation
 *
 * Revision 1.4  2005/12/23 07:49:27  csoutheren
 * Fixed Unix implementation
 *
 * Revision 1.3  2005/12/23 06:44:31  csoutheren
 * Working implementation
 *
 * Revision 1.2  2005/12/22 07:27:36  csoutheren
 * More implementation
 *
 * Revision 1.1  2005/12/22 03:55:52  csoutheren
 * Added initial version of socket aggregation classes
 *
 */

#ifdef __GNUC__
#pragma implementation "sockagg.h"
#endif


#include <ptlib.h>
#include <ptclib/sockagg.h>

#include <fcntl.h>

////////////////////////////////////////////////////////////////

#if _WIN32

class LocalEvent : public PHandleAggregator::EventBase
{
  public:
    LocalEvent()
    { 
      event = CreateEvent(NULL, TRUE, FALSE,NULL); 
      PAssert(event != NULL, "CreateEvent failed");
    }

    ~LocalEvent()
    { CloseHandle(event); }

    PAggregatorFD::FD GetHandle()
    { return event; }

    void Set()
    { SetEvent(event);  }

    void Reset()
    { ResetEvent(event); }

  protected:
    HANDLE event;
};

PAggregatorFD::PAggregatorFD(SOCKET v)
  : socket(v) 
{ 
  fd = WSACreateEvent(); 
  PAssert(WSAEventSelect(socket, fd, FD_READ | FD_CLOSE) == 0, "WSAEventSelect failed"); 
}

PAggregatorFD::~PAggregatorFD()
{ 
  WSACloseEvent(fd); 
}

bool PAggregatorFD::IsValid()
{ 
  return socket != INVALID_SOCKET; 
}

#else // #if _WIN32

class LocalEvent : public PHandleAggregator::EventBase
{
  public:
    LocalEvent()
    { ::pipe(fds); }

    virtual ~LocalEvent()
    {
      close(fds[0]);
      close(fds[1]);
    }

    PAggregatorFD::FD GetHandle()
    { return fds[0]; }

    void Set()
    { char ch; write(fds[1], &ch, 1); }

    void Reset()
    { char ch; read(fds[0], &ch, 1); }

  protected:
    int fds[2];
};

PAggregatorFD::PAggregatorFD(int v)
  : fd(v) 
{ 
}

PAggregatorFD::~PAggregatorFD()
{
}

bool PAggregatorFD::IsValid()
{ 
  return fd >= 0; 
}

#endif // #endif _WIN32
  

////////////////////////////////////////////////////////////////

class WorkerThread : public PHandleAggregator::WorkerThreadBase
{
  public:
    WorkerThread()
      : WorkerThreadBase(localEvent)
    { }

    void Trigger()
    { localEvent.Set(); }

    LocalEvent localEvent;
};


////////////////////////////////////////////////////////////////

PHandleAggregator::PHandleAggregator(unsigned _max)
  : maxWorkerSize(_max), minWorkerSize(1)
{ 
}

BOOL PHandleAggregator::AddHandle(PAggregatedHandle * handle)
{
  PTRACE(4, "Adding handle to socket aggregator thread");

  // perform the handle init function
  if (!handle->Init())
    return FALSE;

  PWaitAndSignal m(mutex);

  // look for a worker thread to use that has less than the maximum number of handles
  WorkerList_t::iterator r;
  for (r = workers.begin(); r != workers.end(); ++r) {
    WorkerThreadBase & worker = **r;
    PWaitAndSignal m2(worker.mutex);
    if (worker.handleList.size() < maxWorkerSize) {
      worker.handleList.push_back(handle);
      worker.listChanged = TRUE;
      worker.Trigger();
      return TRUE;
    }
  }

  // no worker threads usable, create a new one
  //cout << "New worker thread created" << endl;
  WorkerThread * worker = new WorkerThread;
  worker->handleList.push_back(handle);
  worker->Resume();
  workers.push_back(worker);

  return TRUE;
}

BOOL PHandleAggregator::RemoveHandle(PAggregatedHandle * handle)
{
  PTRACE(4, "Removing handles from socket aggregator thread");

  PWaitAndSignal m(mutex);

  // look for the thread containing the handle we need to delete
  WorkerList_t::iterator r;
  for (r = workers.begin(); r != workers.end(); ++r) {
    WorkerThreadBase * worker = *r;

    // lock the worker
    worker->mutex.Wait();

    HandleContextList_t & hList = worker->handleList;

    // if handle is not in this thread, then continue searching
    HandleContextList_t::iterator s = find(hList.begin(), hList.end(), handle);
    if (s == worker->handleList.end()) {
      worker->mutex.Signal();
      continue;
    }

    // remove the handle from the worker's list of handled
    worker->handleList.erase(s);

    // if the worker thread has enough handles to keep running, trigger it to update
    if (worker->handleList.size() >= minWorkerSize) {
      worker->listChanged = TRUE;
      worker->Trigger();
      worker->mutex.Signal();
      return TRUE;
    }

    // remove the worker thread from the list of workers
    workers.erase(r);

    // add it's handles to other threads
    {
      HandleContextList_t::iterator t;
      for (t = hList.begin(); t != hList.end(); ++t)
        AddHandle(*t);
    }

    // trigger and unlock the worker
    worker->Trigger();
    worker->mutex.Signal();

    // the worker is now finished
    worker->WaitForTermination();
    delete worker;

    return TRUE;
  }

  return FALSE;
}

////////////////////////////////////////////////////////////////

typedef std::vector<PAggregatorFD::FD> fdList_t;
typedef std::vector<PAggregatorFD * > aggregatorFdList_t;
typedef std::map<PAggregatorFD::FD, PAggregatedHandle *> aggregatorFdToHandleMap_t;

#ifdef _WIN32
#define	FDLIST_SIZE	WSA_MAXIMUM_WAIT_EVENTS
#else
#define	FDLIST_SIZE	64
#endif

void PHandleAggregator::WorkerThreadBase::Main()
{
  PTRACE(4, "Socket aggregator thread started");

  fdList_t                  fdList;
  aggregatorFdList_t        aggregatorFdList;
  aggregatorFdToHandleMap_t aggregatorFdToHandleMap;

  for (;;) {

    // create the list of fds to wait on and find minimum timeout
    PTimeInterval timeout(PMaxTimeInterval);
    PAggregatedHandle * timeoutHandle = NULL;
    HandleContextList_t handlesToRemove;

#ifndef _WIN32
    fd_set rfds;
    FD_ZERO(&rfds);
    int maxFd = 0;
#endif

    {
      PWaitAndSignal m(mutex);

      // if no handles, then thread is no longer needed
      if (handleList.size() == 0)
        break;

      // if the list of handles has changed, clear the list of handles
      if (listChanged) {
        aggregatorFdList.erase       (aggregatorFdList.begin(),      aggregatorFdList.end());
        aggregatorFdList.reserve     (FDLIST_SIZE);
        fdList.erase                 (fdList.begin(),                fdList.end());
        fdList.reserve               (FDLIST_SIZE);
        aggregatorFdToHandleMap.erase(aggregatorFdToHandleMap.begin(),         aggregatorFdToHandleMap.end());
      }

      HandleContextList_t::iterator r;
      for (r = handleList.begin(); r != handleList.end(); ++r) {
        PAggregatedHandle * handle = *r;

        if (listChanged) {
          PAggregatorFDList_t fds = handle->GetFDs();
          PAggregatorFDList_t::iterator s;
          for (s = fds.begin(); s != fds.end(); ++s) {
            fdList.push_back          ((*s)->fd);
            aggregatorFdList.push_back((*s));
            aggregatorFdToHandleMap.insert(aggregatorFdToHandleMap_t::value_type((*s)->fd, handle));
          }
        }

        if (!handle->IsPreReadDone()) {
          handle->PreRead();
          handle->SetPreReadDone();
        }

        PTimeInterval t = handle->GetTimeout();
        if (t < timeout) {
          timeout = t;
          timeoutHandle = handle;
        }
      }

      // add in the event fd
      if (listChanged) {
        fdList.push_back(event.GetHandle());
        listChanged = FALSE;
      }

#ifndef _WIN32
      fdList_t::iterator s;
      for (s = fdList.begin(); s != fdList.end(); ++s) {
        FD_SET(*s, &rfds);
        maxFd = PMAX(maxFd, *s);
      }
#endif
    }

#ifdef _WIN32
    PTime wstart;
    DWORD nCount = fdList.size();
    DWORD ret = WSAWaitForMultipleEvents(nCount, &fdList[0], false, timeout.GetInterval(), FALSE);

    if (ret == WAIT_FAILED) {
      DWORD err = GetLastError();
      PTRACE(1, "WaitForMultipleObjects error " << err);
    }

    {
      PWaitAndSignal m(mutex);

      if (ret == WAIT_TIMEOUT) {
        PTime start;
        BOOL closed = !timeoutHandle->OnRead();
        unsigned duration = (unsigned)(PTime() - start).GetMilliSeconds();
        if (duration > 50) {
          PTRACE(4, "Warning: aggregator read routine was of extended duration = " << duration << " msecs");
        }
        if (!closed)
          timeoutHandle->SetPreReadDone(FALSE);
        else {
          handlesToRemove.push_back(timeoutHandle);
          timeoutHandle->DeInit();
        }
      }

      else if (WAIT_OBJECT_0 <= ret && ret <= (WAIT_OBJECT_0 + nCount - 1)) {
        DWORD index = ret - WAIT_OBJECT_0;

        // if the event was triggered, redo the select
        if (index == nCount-1) {
          event.Reset();
          continue;
        }

        PAggregatorFD * fd = aggregatorFdList[index];
        PAssert(fdList[index] == fd->fd, "Mismatch in fd lists");
        aggregatorFdToHandleMap_t::iterator r = aggregatorFdToHandleMap.find(fd->fd);
        if (r != aggregatorFdToHandleMap.end()) {
          PAggregatedHandle * handle = r->second;
          WSANETWORKEVENTS events;
          WSAEnumNetworkEvents(fd->socket, fd->fd, &events);
          if (events.lNetworkEvents != 0) {
            BOOL closed = FALSE;
            if ((events.lNetworkEvents & FD_CLOSE) != 0)
              closed = TRUE;
            else if ((events.lNetworkEvents & FD_READ) != 0) {
              PTime start;
              closed = !handle->OnRead();
              unsigned duration = (unsigned)(PTime() - start).GetMilliSeconds();
              if (duration > 50) {
                PTRACE(4, "Warning: aggregator read routine was of extended duration = " << duration << " msecs");
              }
            }
            if (!closed)
              handle->SetPreReadDone(FALSE);
            else {
              handle->DeInit();
              handlesToRemove.push_back(handle);
              listChanged = TRUE;
            }
          }
        }
      }

#else

    P_timeval pv = timeout;
    int ret = ::select(maxFd+1, &rfds, NULL, NULL, pv);

    if (ret < 0) {
      PTRACE(1, "Select failed with error " << errno);
    }

    // loop again if nothing was ready
    if (ret <= 0)
      continue;

    {
      PWaitAndSignal m(mutex);

      if (ret == 0) {
        PTime start;
        BOOL closed = !timeoutHandle->OnRead();
        unsigned duration = (unsigned)(PTime() - start).GetMilliSeconds();
        if (duration > 50) {
          PTRACE(4, "Warning: aggregator read routine was of extended duration = " << duration << " msecs");
        }
        if (!closed)
          timeoutHandle->SetPreReadDone(FALSE);
        else {
          handlesToRemove.push_back(timeoutHandle);
          timeoutHandle->DeInit();
        }
      }

      // check the event first
      else if (FD_ISSET(event.GetHandle(), &rfds)) {
        event.Reset();
        continue;
      }

      else {
        PAggregatorFD * fd = aggregatorFdList[ret];
        PAssert(fdList[ret] == fd->fd, "Mismatch in fd lists");
        aggregatorFdToHandleMap_t::iterator r = aggregatorFdToHandleMap.find(fd->fd);
        if (r != aggregatorFdToHandleMap.end()) {
          PAggregatedHandle * handle = r->second;
          PTime start;
          BOOL closed = !handle->OnRead();
          unsigned duration = (unsigned)(PTime() - start).GetMilliSeconds();
          if (duration > 50) {
            PTRACE(4, "Warning: aggregator read routine was of extended duration = " << duration << " msecs");
          }
          if (!closed)
            handle->SetPreReadDone(FALSE);
          else {
            handle->DeInit();
            handlesToRemove.push_back(handle);
            listChanged = TRUE;
          }
        }
      }

#endif

      // remove handles that are now closed
      while (handlesToRemove.begin() != handlesToRemove.end()) {
        PAggregatedHandle * handle = *handlesToRemove.begin();
        handlesToRemove.erase(handlesToRemove.begin());
        HandleContextList_t::iterator r = find(handleList.begin(), handleList.end(), handle);
        if (r != handleList.end())
          handleList.erase(r);
        if (handle->autoDelete) 
          delete handle;
      }
    }
  }

  PTRACE(4, "Socket aggregator thread finished");
}

