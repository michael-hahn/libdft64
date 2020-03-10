#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <string>
#include <map>
#include <set>
#include <vector>

#include "branch_pred.h"
#include "libdft_api.h"
#include "pin.H"
#include "tagmap.h"
#include "debug.h"
#include "syscall_hook.h"
#include "osutils.h"
#include "helper.h"

/* Set of interesting addresses to track. */
static std::set<ADDRINT> addrset;

/* Pin knobs. */
/* Track open/create files (enabled by default). */
static KNOB<size_t> fs(KNOB_MODE_WRITEONCE, "pintool", "f", "1", "Enable files as taint sources.");
/* Track socket connections (enabled by default). */
static KNOB<size_t> sk(KNOB_MODE_WRITEONCE, "pintool", "s", "1", "Enable sockets as taint sources.");
/* Splice log file path (different from the Pin's native log LOG()) */
static KNOB<string> log_path(KNOB_MODE_WRITEONCE, "pintool", "l", "splice.log", "File path of the Splice log.");
/* Time out for debugger connection (default is wait forever). */
static KNOB<UINT32> to(KNOB_MODE_WRITEONCE, "pintool", "t", "0", "When breakpoint condition is triggered, wait for this many seconds for debugger to connect (zero means wait forever)");

/* Called when a new instruction's memory address is 
 * of interest. Insert the address in addrset set. */
VOID addaddrset(ADDRINT addr)
{
	std::cout << "Inserting memory address: " << StringFromAddrint(addr) << std::endl;
	addrset.insert(addr);
}

/*
 * If a debugger is not already connected, ask the user to connect one now.  Upon
 * return, a debugger may or may not be connected.
 */
void ConnectDebugger()
{
	std::ostream *Output = &std::cerr;    
	if (PIN_GetDebugStatus() != DEBUG_STATUS_UNCONNECTED)
		return;

	DEBUG_CONNECTION_INFO info;
	if (!PIN_GetDebugConnectionInfo(&info) || info._type != DEBUG_CONNECTION_TYPE_TCP_SERVER) {
		std::cout << "Debugger already connected.\n";
		return;
	}

	*Output << "Breakpoint triggered.\n";
	*Output << "Start GDB and enter this command:\n";
	*Output << "  target remote :" << std::dec << info._tcpServer._tcpPort << "\n";
	*Output << std::flush;

	if (PIN_WaitForDebuggerToConnect(1000*to.Value()))
		return;

	*Output << "No debugger attached after " << to.Value() << " seconds.\n";
	*Output << "Resuming application without stopping.\n";
	*Output << std::flush;
}

/* Analysis routine called if we should stop at a breakpoint. */
VOID DoBreakpoint(const CONTEXT *ctxt, THREADID tid)
{
	ConnectDebugger(); // Ask the user to connect a debugger, if not already connected.
	std::ostringstream msg;
	msg.str("A breakpoint is triggered.\n");
	// msg << "Stack pointer: " << PIN_GetContextReg(ctxt, REG_STACK_PTR) << "\n";
	PIN_ApplicationBreakpoint(ctxt, tid, FALSE, msg.str());
}

/* For each routine that is called by the main executable, log its name. */
VOID Routine(RTN rtn, VOID *v)
{
	if (IMG_IsMainExecutable(SEC_Img(RTN_Sec(rtn))))
		std::cout << "Main executable's function: " << RTN_Name(rtn) << std::endl;
}

/* Analysis routine called after each instruction that modifies the stack pointer.
 * It simply returns true.
 * TODO: ideally, we want to check if the stack change is positive or negative 
 * to determine if a function is about to be popped off the stack or added to it.
 * We want to check taints before the function is to be popped off. */
ADDRINT OnStackChangeIf(ADDRINT sp)
{
	return 1;
}

/* For each instruction, if the instruction modifies the stack pointer, then the
 * OnStackChangeIf call back will be called to check the condition. If the 
 * condition fulfills, then the DoBreakpoint call back will be called. 
 * TODO: this function is problematic. See the notes below. */
VOID Instruction(INS ins, VOID *v)
{
	if (INS_RegWContain(ins, REG_STACK_PTR)) {
		IPOINT where = IPOINT_BEFORE;

		INS_InsertIfCall(ins, where, (AFUNPTR)OnStackChangeIf, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
		INS_InsertThenCall(ins, where, (AFUNPTR)DoBreakpoint, IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
	}

}

/* Set a breakpoint at after a function's last instruction. 
 * NOTE: YOU CANNOT SET A BREAKPOINT BEFORE AN INSTRUCTION!
 * NOTE: That is, loc cannot be IPOINT_BEFORE; otherwise,
 * NOTE: the program cannot proceed!*/
VOID SetAfterFuncTailBreakpoint(RTN func)
{
	RTN_Open(func);
	INS ins_tail = RTN_InsTail(func);
	IPOINT loc = IPOINT_AFTER;

	if (!INS_HasFallThrough(ins_tail))
		loc = IPOINT_TAKEN_BRANCH;
	INS_InsertCall(ins_tail, loc, (AFUNPTR)DoBreakpoint, IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
	RTN_Close(func);
}

/* Called when a new image is loaded (debugging mode). */
VOID ImageLoadDebug(IMG img, VOID *v)
{
	std::string exename;

	/* The following commented code prints out all the function symbols in main executable.*/
	/*
	if (IMG_IsMainExecutable(img)) {
		for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
				printf("Function: %s\n", RTN_Name(rtn).c_str());
			}
		}
		exit(1);
	}
	*/
	if (IMG_IsMainExecutable(img)) {
		exename = path_resolve(IMG_Name(img));
		std::cout << "Debugging: " << exename << std::endl;
	
		/* Set a breakpoint right before the client's query buffer is processed. 
		 * This breakpoint should be set right after clear_client_reply function
		 * in on_read_cb function. */
		RTN func = RTN_FindByName(img, "clear_client_reply");
		if (RTN_Valid(func)) {
			std::cout << "Setting a breakpoint right after " <<  RTN_Name(func) << " returns.\n";
			SetAfterFuncTailBreakpoint(func);
		} else {
			std::cout << "Cannot find function: clear_client_reply\n";
		}

		/* Set a breakpoint after the client's query buffer is processed. */
		func = RTN_FindByName(img, "call");
		if (RTN_Valid(func)) {
			std::cout << "Setting a breakpoint right after " << RTN_Name(func) << " returns.\n";
			/*
			RTN_Open(func);

			IPOINT loc = IPOINT_AFTER;
			INS ins_head = RTN_InsHead(func);
			if (!INS_HasFallThrough(ins_head))
				loc = IPOINT_TAKEN_BRANCH;
			INS_InsertCall(ins_head, loc, (AFUNPTR)DoBreakpoint, IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);

			INS ins_tail = RTN_InsTail(func);
			loc = IPOINT_AFTER;
			if (!INS_HasFallThrough(ins_tail))
				loc = IPOINT_TAKEN_BRANCH;
			INS_InsertCall(ins_tail, loc, (AFUNPTR)DoBreakpoint, IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
			
			RTN_Close(func);
			*/
			SetAfterFuncTailBreakpoint(func);

		} else {
			std::cout << "Cannot find function: call\n";
		}

		/* Set a breakpoint after the server has completed the client's request,
		 * and ready to accept the next request from the client. */
		func = RTN_FindByName(img, "flush_client_offset");
		if (RTN_Valid(func)) {
			std::cout << "Setting a breakpoint right after " << RTN_Name(func) << " returns.\n";
			SetAfterFuncTailBreakpoint(func);
		} else {
			std::cout << "Cannot find function: flush_client_offset\n";
		}
	}
}

/* Called when a new image is loaded (debug & non-debugging mode). */
VOID ImageLoad(IMG img, VOID *v)
{
	std::string exename;

	if (IMG_IsMainExecutable(img)) {
		exename = path_resolve(IMG_Name(img));
		std::cout << "Loading: " << exename << std::endl;
		/* Register Routine to be called as the main executable is loaded. */
		// RTN_AddInstrumentFunction(Routine, 0);
		
		/* Identify the function we want to track. */
		RTN func = RTN_FindByName(img, "init_owner");
		if (RTN_Valid(func)) {
			std::cout << "Tracking function: " << RTN_Name(func) << std::endl;
			
			/* Instrument the instructions in the function. */
			RTN_Open(func);

			for (INS ins = RTN_InsHead(func); INS_Valid(ins); ins = INS_Next(ins)) {
				if (INS_IsMemoryRead(ins) &&
				    INS_OperandIsMemory(ins, 1)) {
					std::cout << "Memory Read Instruction (Opcode): " << INS_Mnemonic(ins) << std::endl;
					INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(addaddrset), IARG_MEMORYREAD_EA, IARG_END);
				}
				if (INS_IsMemoryWrite(ins)) {
					std::cout << "Memory Write Instruction (Opcode): " << INS_Mnemonic(ins) << std::endl;					
					INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(addaddrset), IARG_MEMORYWRITE_EA, IARG_END);
				}
			}

			RTN_Close(func);
		}
	}
}

/* Called when a new image is unloaded. 
 * We are printing out the entire tag map. */
VOID ImageUnload(IMG img, VOID *v)
{
	if (IMG_IsMainExecutable(img)) {
		std::cout << "Main executable is unloaded\n";	
	}
}
	
/* This call-back implements extended debugger commands. 
 * tid[in]: 		Pin thread ID for debugger's "focus" thread.
 * ctxt[in, out]:	Register state for the debugger's "focus" thread.
 * cmd[in]:		text of the extended command
 * result[out]:		text that the debugger prints when the command finsihes. */
BOOL DebugInterpreter(THREADID tid, CONTEXT *ctxt, const string &cmd, string *result, VOID *)
{
	std::string line = TrimWhitespace(cmd);
	*result = "";

	if (line == "help") {
		result->append("visual table		--Visualize the entire tagmap per table.\n");
		result->append("visual page		--Visualize the entire tagmap per page.\n");
		result->append("lookup <addr>		--Look up the taint at the given memory address <addr>.\n");		
		return TRUE;
	} else if (line == "visual table") {
		result->append("Not implemented in x64.\n");
		return TRUE;
	} else if (line == "visual page") {
		result->append("Not implemented in x64.\n");
		return TRUE;
	} else if (line.find("lookup ") == 0) {
		std::istringstream is(&line.c_str()[sizeof("lookup ")-1]);
		unsigned long addr;
		is >> std::hex >> addr;
		if (!is) {
			*result = "Please specify a memory address (0xADDR)\n";
			return TRUE;
		}
		tag_t tag = tagmap_getb(addr);
		result->append("[ ");
		result->append(StringFromAddrint(addr));
		result->append(" ]-> ");
		result->append(tag_sprint(tag));
		result->append("\n");		
		return TRUE;
	}
	return FALSE; /* Unknown command */
}

int
main(int argc, char **argv)
{
	/* initialize symbol processing */
	PIN_InitSymbols();
       
	/* initialize Pin; optimized branch */
	if (unlikely(PIN_Init(argc, argv)))
		/* Pin initialization failed */
		goto err;

	/* Certain functionality is only enabled if
	 * application level debugging is enabled. */
	if (PIN_GetDebugStatus() == DEBUG_STATUS_DISABLED) {
		LOG("Warning: Application level debugging must be enabled to use certain functionality of this tool\n");
		LOG("Start Pin with either -appdebug or -appdebug_enable. \n");
	} else {
		PIN_AddDebugInterpreter(DebugInterpreter, 0);
		/* Register ImageLoad debug function to be called when an image is loaded. We only log the main executable. */
		IMG_AddInstrumentFunction(ImageLoadDebug, 0);
	}

	// Register Routine to be called to instrument rtn
	// RTN_AddInstrumentFunction(Routine, 0);

	// PIN_AddFiniFunction(OnExit, 0);

	LOG("Initializing libdft...\n");
	/* initialize the core tagging engine */
	if (unlikely(libdft_init() != 0))
		/* failed */
		goto err;

	/* Open Splice log file to ofstream out. */
	// out.open(log_path.Value().c_str());

	/* Register ImageLoad function to be called when an image is loaded. We only log the main executable. */
	// IMG_AddInstrumentFunction(ImageLoad, 0);
	// INS_AddInstrumentFunction(Instruction, 0);

	/* Register ImageUnload function to be called when an image is unloaded. */
	IMG_AddUnloadFunction(ImageUnload, 0);

	/* Install taint sources and sinks through syscall hooking. */
	hook_syscall();

	LOG("Starting Program...\n");
	/* start Pin */
	PIN_StartProgram();

	/* typically not reached; make the compiler happy */
	return EXIT_SUCCESS;

err:	/* error handling */

	libdft_die();

	/* return */
	return EXIT_FAILURE;
}
