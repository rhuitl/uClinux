# Makefile for Network-Usage Monitor for LRP (or any other Linux)

# Lrp Network Monitor: Simple network monitor written in Java
# Copyright (C) 2002 Martin Hejl
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

CLASSPATH = $(shell pwd)

JAVAC = javac -deprecation
JAVA = java
JRE = jre
JAR = jar

JARFILE = lrpstat.jar

$(JARFILE): LrpStatApplet.class LrpStatApplication.class Debug.class
	$(JAR) -cf $(JARFILE) *.class 

LrpStatApplet.class: LrpStatApplet.java LrpStatModelListener.class LrpStatModel.class InterfaceInfo.class InterfaceOptions.class CommandInfo.class LrpStatModelEvent.class LrpStatAbstractGraph.class LrpStatBarGraph.class LrpStatNumericGraph.class LrpStatHistGraph.class LrpStatDoubleHistGraph.class LrpStatLineGraph.class Debug.class
	$(JAVAC) LrpStatApplet.java

NetworkConnection.class: NetworkConnection.java InterfaceInfoParser.class InterfaceInfo.class Debug.class
	$(JAVAC) NetworkConnection.java
	
InterfaceInfoParser.class: InterfaceInfoParser.java InterfaceInfo.class InterfaceOptions.class Debug.class
	$(JAVAC) InterfaceInfoParser.java

CpuStats.class: CpuStats.java Debug.class
	$(JAVAC) CpuStats.java 

InterfaceInfo.class: InterfaceInfo.java CpuStats.class Debug.class 
	$(JAVAC) InterfaceInfo.java
	
InterfaceOptions.class: InterfaceOptions.java CommandInfo.class Debug.class
	$(JAVAC) InterfaceOptions.java

CommandInfo.class: CommandInfo.java Debug.class
	$(JAVAC) CommandInfo.java

LrpStatModel.class: LrpStatModel.java LrpStatModelListener.class LrpStatModelEvent.class NetworkConnection.class  Debug.class LongRingBuffer.class
	$(JAVAC) LrpStatModel.java

LrpStatModelEvent.class: LrpStatModelEvent.java InterfaceOptions.class InterfaceInfo.class Debug.class
	$(JAVAC) LrpStatModelEvent.java

LrpStatModelListener.class: LrpStatModelListener.java LrpStatModelEvent.class Debug.class
	$(JAVAC) LrpStatModelListener.java

LrpStatAbstractGraph.class: LrpStatAbstractGraph.java InterfaceInfo.class InterfaceOptions.class LrpStatLook.class LongRingBuffer.class Debug.class LrpStatAction.class
	$(JAVAC) LrpStatAbstractGraph.java	

LrpStatBarGraph.class: LrpStatBarGraph.java LrpStatAbstractGraph.class Debug.class
	$(JAVAC) LrpStatBarGraph.java	

LrpStatNumericGraph.class: LrpStatNumericGraph.java LrpStatAbstractGraph.class  Debug.class
	$(JAVAC) LrpStatNumericGraph.java	
	
LrpStatHistGraph.class: LrpStatHistGraph.java LrpStatAbstractGraph.class  Debug.class
	$(JAVAC) LrpStatHistGraph.java	

LrpStatDoubleHistGraph.class: LrpStatDoubleHistGraph.java LrpStatAbstractGraph.class Debug.class
	$(JAVAC) LrpStatDoubleHistGraph.java	
	
LrpStatLineGraph.class: LrpStatLineGraph.java LrpStatAbstractGraph.class  Debug.class
	$(JAVAC) LrpStatLineGraph.java 
	
LrpStatLook.class: LrpStatLook.java Debug.class
	$(JAVAC) LrpStatLook.java 

LrpGraphFactory.class: LrpGraphFactory.java LrpAbstractGraph.class Debug.class
	$(JAVAC) LrpGraphFactory.java 

LongRingBuffer.class: LongRingBuffer.java LongEnumeration.class RingBufferException.class  Debug.class
	$(JAVAC) LongRingBuffer.java 

LongEnumeration.class: LongEnumeration.java Debug.class
	$(JAVAC) LongEnumeration.java 

RingBufferException.class: RingBufferException.java Debug.class
	$(JAVAC) RingBufferException.java 
	
LrpStatApplication.class: LrpStatApplication.java LrpStatApplet.class Debug.class
	$(JAVAC) LrpStatApplication.java 

LrpStatAction.class: LrpStatAction.java CommandInfo.class 
	$(JAVAC) LrpStatApplication.java 

Debug.class: Debug.java
	$(JAVAC) Debug.java 


romfs:
	-mkdir java
	$(ROMFSINST) /home/httpd/java
	-rm -rf java
	$(ROMFSINST) /home/httpd/java/$(JARFILE)
	#$(ROMFSINST) /home/httpd/Netmon.html

clean: 
	-rm -f *.class *.jar
