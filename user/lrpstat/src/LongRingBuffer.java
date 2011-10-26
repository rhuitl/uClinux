// Lrp Network Monitor: Simple network monitor written in Java
// Copyright (C) 2001 Martin Hejl
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

// $Revision: 1.7 $
// $Author: hejl $
// $Header: /home/cvs/lrpStat/src/LngRingBuffer.java,v 1.7 2002/03/12 22:19:13 hejl Exp $

/**
 * This class implements a ring (filo) buffer. Pushing and pulling
 * is most effective.
 * <p><b>Hopefully, this class is thread save!</b>
 *
 * @author       Martin Hejl
 * @version      20020309 0.13beta
 */

public class LongRingBuffer
{
	protected int nSize;			// Maximum size, before the buffer wraps
  	protected int nRoot;			// First element
  	protected int nTail; 			// Last element
  	protected int nElementCount; 	// Number of used elements
  	protected long[] lElements;       // The array that holds the elements for the RingBuffer
  	protected boolean bLocked;       // Indicates wether data can be read/written
  	protected long lMax=0;
  	protected long lMin=0;
  	protected static final int BUFFER_INCREMENT=128;

	/**
	 * Initialize with specific size
	 * @param size Size of the buffer.
	 */
	public LongRingBuffer (int size){
		bLocked = false;
		nSize=size;
		lElements = new long[size];
		clear();
	}

	/**
	 * Initialize with default size (128).
	 */
	public LongRingBuffer (){
		this(128);
	}

	/**
	 * Clear the ring buffer.
	 */
	public void clear (){
		nElementCount = 0;
		nRoot         = 0;
		nTail         = 0;
	}

	/**
	 * Resizes the Buffer. Old values will not get lost (the additional space will
	 * be appended to the end of the buffer). If neccessary the contents of the
	 * buffer are copied to a new buffer
	 * WARNING!!! Must be called inside of a lock/unlock block!!!!
	 * @param newSize The new size of the rinbuffer.
	 */
	protected void setSize(int newSize) {
		long[] newBuffer;
		int position;;

		newBuffer = new long[newSize];

		/* Copy the data (resort it at the same time) */
		position=nRoot;
		for (int i=0; i<nElementCount && i<newSize; i++) {
			newBuffer[i] = lElements[position++];
			if (position>=nSize) position=0;
		}
		nRoot = 0;

		// if the new size is smaller than the old one, clip the old data
		if (nElementCount>newSize) {
			nElementCount=newSize;
		}

		lElements = newBuffer;
		nSize = newSize;
		nTail = (nRoot + nElementCount)% nSize;

	}

	/**
	 * Returns the current size of the buffer (the maximum number of elements the buffer can hold without wrapping)
	 */
	public int getSize() {
		return(nSize);
	}

	/**
	 * Test if the buffer is empty.
	 */
	public boolean isEmpty (){
		return(nElementCount==0);
	}

	/**
	 *Test if the buffer is full.
	 */
	public boolean isFull (){
		return(nElementCount>=nSize);
	}

	/**
	 * Add a new element at the end of the buffer <BR>
	 * Resizes the buffer automatically if needed
	 * @param x Value to be pushed.
	 */
	public void push (long l) {
		lock();

		if (isFull()) {
			setSize(nSize+BUFFER_INCREMENT);
			Debug.println("Setting size to " + nSize);
		}


		try {
			lElements[nTail]=l;
		} catch (ArrayIndexOutOfBoundsException e)
		{
			System.err.println("Exception caught:");
			System.err.println("lRoot=" + nTail);
			System.err.println("lTail=" + nTail);
			System.err.println("lElementCount=" + nElementCount);
			System.err.println("lSize=" + nSize);
			e.printStackTrace();

		}

		// Recalculate min and max if neccessary
		if (l>lMax) lMax=l;
		if (l<lMin) lMin=l;

		nTail++;
		nElementCount++;

		// Wrap the pointer if necessary
		if (nTail>=nSize) nTail=0;
		unlock();
	}

	/**
	 * Pop the first element from the buffer or throw
	 * RingBufferEmptyException.
	 * @return First buffer element
	 */
	public long pop() throws RingBufferException {
		long retVal;

		if (nElementCount==0) throw new RingBufferException();

		lock();
		retVal = lElements[nRoot];

		nRoot++;
		nElementCount--;

		// Wrap the pointer if necessary
		if (nRoot>=nSize) nRoot=0;

		// Recalculate min and max if neccessary
		if (retVal>=lMax || retVal<=lMin) {
			lMax = retVal;
			lMin = retVal;
			for (int i=0; i<nElementCount; i++) {
				if (lElements[i]>lMax) lMax=lElements[i];
				if (lElements[i]<lMin) lMin=lElements[i];
			}

		}

		unlock();
		return(retVal);
	}

	/**
	 * @return Number of available elements.
	 */
	public int getElementCount() {
		return(nElementCount);
	}

	/**
	 * Get a value by its number.
	 * Empty buffers will return "0", too large indices
	 * will wrap until the index is inside the buffer
	 * @param index Number of element to retrieve
	 * @return Element number index
	 */
	public long elementAt(int index) {
		lock();
		long val = lElements[(nRoot + index) % nSize];
		unlock();

		return(val);
	}

	/**
	 * @retun Enumeration with the contents of the buffer
	 */
	public java.util.Enumeration elements() {
		LongEnumeration retVal;

		lock();
		retVal = new LongEnumeration(nElementCount);

		for (int i=0; i<nElementCount; i++) {
			retVal.addElement(lElements[(nRoot + i) % nSize]);
		}
		unlock();

		retVal.rewind();
		return((java.util.Enumeration)retVal);
	}

	/**
	 * locks the object for reading
	 * needs to be done from the calling class, if you want to loop through the contents without
	 * using the enumeration (until all objects have been retrieved, it would be best to not change
	 * the contents
	 */
	protected synchronized void lock() {
		//if (!s.equals("")) System.err.println("Lock " + s);
		while (tryToGrabLock() == false) {
			try {
				//System.err.println("Waiting for lock");
				wait(250);
			} catch (Exception e) {}
		}
	}

	protected synchronized boolean tryToGrabLock() {
		if (bLocked == false) {
			bLocked = true;
			return(true);
		}
		return false;
	}

	/**
	 *
	 */
	protected synchronized void unlock() {
		//if (!s.equals(""))  System.err.println("UnLock " + s);
		bLocked = false;
		notifyAll();
	}

	/**
	 *
	 */
	public long max(){
		return(lMax);
	}

	/**
	 *
	 */
	public long min(){
		return(lMin);
	}

}