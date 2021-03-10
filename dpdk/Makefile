
TOOL_DIRS = pkt-mirror
TOOL_DIRS += smv9-2-publisher


all:	tools

tools:
	-for d in $(TOOL_DIRS); do(cd $$d && $(MAKE)); done

clean:
	-for d in $(TOOL_DIRS); do(cd $$d && $(MAKE) clean); done
	
install:
	-for d in $(TOOL_DIRS); do(cd $$d && $(MAKE) install); done
