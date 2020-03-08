#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <map>
#include <vector>
#include <math.h>

#include "hooks.h"
#include "osutils.h"
#include "branch_pred.h"
#include "libdft_api.h"
#include "syscall_desc.h"
#include "pin.H"
#include "tagmap.h"
#include "qdbmp.h"

/* default suffixes for dynamic shared libraries.
 * We will use suffixes to identify them to not track them. */
#define DLIB_SUFF 	".so"
#define DLIB_SUFF_ALT 	".so."

/* Macros related to stdin/stdout/stderr. */
#define IS_STDFD(fd) ( (fd == STDOUT_FILENO) || (fd == STDIN_FILENO) || (fd == STDERR_FILENO) )

/* RGB color struct. */
typedef struct RGB
{
	std::string color;
	int r, g, b;
} RGB;

/* Predefine some distinct colors. */
#define MAROON 		RGB { .color="MAROON"  , .r=128, .g=0  , .b=0   }
#define BROWN 		RGB { .color="BROWN"   , .r=170, .g=110, .b=40  }
#define OLIVE		RGB { .color="OLIVE"   , .r=128, .g=128, .b=0   }
#define TEAL		RGB { .color="TEAL"    , .r=0  , .g=128, .b=128 }
#define NAVY		RGB { .color="NAVY"    , .r=0  , .g=0  , .b=128 }
#define BLACK		RGB { .color="BLACK"   , .r=0  , .g=0  , .b=0   }
#define RED		RGB { .color="RED"     , .r=230, .g=25 , .b=75  }
#define ORANGE		RGB { .color="ORANGE"  , .r=245, .g=130, .b=48  }
#define YELLOW		RGB { .color="YELLOW"  , .r=255, .g=225, .b=25  }
#define LIME		RGB { .color="LIME"    , .r=210, .g=245, .b=60  }
#define GREEN		RGB { .color="GREEN"   , .r=60 , .g=180, .b=75  }
#define CYAN		RGB { .color="CYAN"    , .r=70 , .g=240, .b=240 }
#define BLUE		RGB { .color="BLUE"    , .r=0  , .g=130, .b=200 }
#define PURPLE		RGB { .color="PURPLE"  , .r=145, .g=30 , .b=180 }
#define MAGENTA		RGB { .color="MAGENTA" , .r=240, .g=50 , .b=230 }
#define GREY		RGB { .color="GREY"    , .r=128, .g=128, .b=128 }
#define PINK		RGB { .color="PINK"    , .r=250, .g=190, .b=190 }
#define APRICOT		RGB { .color="APRICOT" , .r=255, .g=215, .b=180 }
#define BEIGE		RGB { .color="BEIGE"   , .r=255, .g=250, .b=200 }
#define MINT		RGB { .color="MINT"    , .r=170, .g=255, .b=195 }
#define LAVENDER	RGB { .color="LAVENDER", .r=230, .g=190, .b=255 }
#define WHITE		RGB { .color="WHITE"   , .r=255, .g=255, .b=255 }

/* We define an array of colors a file descriptor can be assigned to. 
 * We will not exhaust all the colors defined above since some may be
 * used as contrast colors. */
std::vector<RGB> fd_colors = { MAROON, TEAL, NAVY, RED, ORANGE, LIME, BLUE, PURPLE, MAGENTA, BEIGE };

/* Not used at the moment, but must declare here
 * since it is declared extern somewhere else 
 * in libdft core. */
std::ofstream lea_offset;

extern tag_dir_t tag_dir;

/* Syscall descriptors. */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* Set of interesting descriptors to track. */
static set<int> fdset;

/* Maps descriptors to colors for visualization. */
static map<int, RGB> fdmap;

/* Set of interesting addresses to print at the end. */
static set<ADDRINT> addrset;

/* Pin knobs. */
/* Track open/create files (enabled by default). */
static KNOB<size_t> fs(KNOB_MODE_WRITEONCE, "pintool", "f", "1", "Enable files as taint sources.");

/* Track socket connections (enabled by default). */
static KNOB<size_t> sk(KNOB_MODE_WRITEONCE, "pintool", "s", "1", "Enable sockets as taint sources.");

/* Splice log file path (different from the Pin's native log LOG()) */
static KNOB<string> log_path(KNOB_MODE_WRITEONCE, "pintool", "l", "splice.log", "File path of the Splice log.");

/* Time out for debugger connection (default is wait forever). */
static KNOB<UINT32> to(KNOB_MODE_WRITEONCE, "pintool", "t", "0", "When breakpoint condition is triggered, wait for this many seconds for debugger to connect (zero means wait forever)");

std::string TrimWhitespace(const std::string &);


/* Called when a new instruction's memory address is 
 * of interest. Insert the address in addrset set. */
VOID addaddrset(ADDRINT addr)
{
	out << "Inserting memory address: "
	    << StringFromAddrint(addr)
	    << "\n";
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
		printf("Debugger already connected.\n");
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
	if (IMG_IsMainExecutable(SEC_Img(RTN_Sec(rtn)))) {
		out << "Main executable's function: "
		    << RTN_Name(rtn)
		    << "\n";
	}
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
		out << "Debugging: "
		    << exename
		    << "\n";
	
		/* Set a breakpoint right before the client's query buffer is processed. 
		 * This breakpoint should be set right after clear_client_reply function
		 * in on_read_cb function. */
		RTN func = RTN_FindByName(img, "clear_client_reply");
		if (RTN_Valid(func)) {
			out << "Setting a breakpoint right after "
			    << RTN_Name(func)
			    << " returns.\n";
			SetAfterFuncTailBreakpoint(func);
		} else {
			out << "Cannot find function: clear_client_reply\n";
		}

		/* Set a breakpoint after the client's query buffer is processed. */
		func = RTN_FindByName(img, "call");
		if (RTN_Valid(func)) {
			out << "Setting a breakpoint right after "
			    << RTN_Name(func)
			    << " returns.\n";
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
			out << "Cannot find function: call\n";
		}

		/* Set a breakpoint after the server has completed the client's request,
		 * and ready to accept the next request from the client. */
		func = RTN_FindByName(img, "flush_client_offset");
		if (RTN_Valid(func)) {
			out << "Setting a breakpoint right after "
			    << RTN_Name(func)
			    << " returns.\n";
			SetAfterFuncTailBreakpoint(func);
		} else {
			out << "Cannot find function: flush_client_offset\n";
		}
	}
}

/* Called when a new image is loaded (debug & non-debugging mode). */
VOID ImageLoad(IMG img, VOID *v)
{
	std::string exename;

	if (IMG_IsMainExecutable(img)) {
		exename = path_resolve(IMG_Name(img));
		out << "Loading: "
		    << exename
		    << "\n";
		/* Register Routine to be called as the main executable is loaded. */
		// RTN_AddInstrumentFunction(Routine, 0);
		
		/* Identify the function we want to track. */
		RTN func = RTN_FindByName(img, "init_owner");
		if (RTN_Valid(func)) {
			out << "Tracking function: "
			    << RTN_Name(func)
			    << "\n";
			
			/* Instrument the instructions in the function. */
			RTN_Open(func);

			for (INS ins = RTN_InsHead(func); INS_Valid(ins); ins = INS_Next(ins)) {
				if (INS_IsMemoryRead(ins) &&
				    INS_OperandIsMemory(ins, 1)) {
					out << "Memory Read Instruction: "
					    << "(Opcode) "
					    << INS_Mnemonic(ins) << "\n";
					INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(addaddrset), IARG_MEMORYREAD_EA, IARG_END);
				}
				if (INS_IsMemoryWrite(ins)) {
					out << "Memory Write Instruction: "
					    << "(Opcode) "
					    << INS_Mnemonic(ins) << "\n";					
					INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(addaddrset), IARG_MEMORYWRITE_EA, IARG_END);
				}
			}

			RTN_Close(func);
		}
	}
}

/* Print out the entire tag map. 
 * There are a total of DIR_SZ * DIR_TABLE_SZ * DIR_PAGE_SZ 
 * tags in the tag map, where those macros are defined in
 * tagmap_custom.h:
 * DIR_SZ = 2^10 
 * DIR_TABLE_SZ = 2^10
 * DIR_PAGE_SZ = 2^12 */
VOID PrintTagMap(void)
{
	unsigned long address = 0;
	for (const auto& table : tag_dir) {
		if (table != NULL) {
			for (const auto& page : *table) {
				if (page != NULL) {
					bool has_tag = false;
					for (const auto& tag : *page) {
						has_tag |= tag_count(tag);
					}
					if (has_tag) {
						out << "< " << StringFromAddrint(address) << " > (Table: " << virt2table(address) << ", Page: " << virt2page(address) << "): ";
						for (const auto& tag : *page) { 
							out << tag_sprint(tag);
						}
						out << "\n";
					}
				}
				address += (1 << 12);
			}
		} else {
			address += (1 << 10) * (1 << 12);
		}
	}
}

/* List all the memory addresses that are tainted.
 * The list is stored in the string format. */
VOID ListAll(string *res)
{
	unsigned long address = 0;
	for (const auto& table : tag_dir) {
		if (table != NULL) {
			for (const auto& page : *table) {
				if (page != NULL) {
					for (const auto& tag : *page) {
						if (tag_count(tag)) {		
							res->append(StringFromAddrint(address));
							res->append(": ");
							res->append(tag_sprint(tag));
							res->append("\n");
						}
						address += 1;
					}
				} else {
					address += (1 << 12);
				}
			}
		} else {
			address += (1 << 10) * (1 << 12);
		}
	}
}

/* Visualize Tag map (per table) using bit map figure. 
 * A BMP file (whose name corresponds to the table ID) exists
 * if and only if there is at least one byte is tainted.
 * In a BMP file (i.e., a table), each pixel is a byte,
 * and a vertical column is a page.
 * If a pixel is WHITE (RGB<255,255,255>), it is not tainted.
 * Taint colors are unique to each type of taint (which
 * corresponds to each fd/user). If a memory address is tained
 * by multiple taints, we give the same taint color regardless
 * of what taints are at the address. For example:
 * Scenario 1:
 * User 1: BLUE
 * User 2: PINK
 * User 1 && 2: GREEN
 * 
 * Scenario 2:
 * User 1: BLUE
 * User 2: PINK
 * User 3: GREY
 * User 1 && 2: GREEN
 * User 1 && 3: GREEN
 * User 2 && 3: GREEN
 * 
 * In scenario 1, we handle it correctly since a green taint
 * means the memory address is tainted by both user 1 and 2.
 * In scenario 2 however, we are unable to differentiate who
 * taint the memory address if we see a green taint. */
VOID VisualizeTagMapTable(void)
{
	unsigned long address = 0x0;
	UINT height = DIR_TABLE_SZ;
	UINT width = DIR_PAGE_SZ;
	for (const auto& table : tag_dir) {
		if (table != NULL) {
			/* Skip the entire table if no pages within are tagged. */
			bool no_skip_table = false;
			for (const auto& page : *table) {
				if (page != NULL) {
					for (const auto& tag : *page) {
						no_skip_table |= tag_count(tag);
					}
				}
			}
			if (!no_skip_table) {
				address += (1 << 10) * (1 << 12);
				continue;
			}
			/* Prepare to visualize the entire page table. */
			BMP* bmp = BMP_Create(height, width, 32);
			if (BMP_GetError() != BMP_OK) {
				printf("An error has occurred: %s (code %d)\n", BMP_GetErrorDescription(), BMP_GetError());
				BMP_Free(bmp);
				return;
			}
			char imageFileName[50];
			sprintf(imageFileName, "figs/%lu.bmp", virt2table(address));
			int i = 0;
			for (const auto& page : *table) {
				if (page != NULL) {
					int j = 0;
					for (const auto& tag : *page) {
						bool has_tag = tag_count(tag);
						if (has_tag) {
							/* A memory location may be tagged with multiple taints. */
							std::vector<size_t> poses = tag.toArray();
							/* If a memort location has only one taint, we visualize it
							 * with its corresponding tag color. */
							if (poses.size() == 1) {
								RGB tag_color = fdmap[(int)poses[0]];
								BMP_SetPixelRGB(bmp, i, j, tag_color.r, tag_color.g, tag_color.b);
							} else {
								/* Visualizing multiple taint colors can be tricky. We simplify
							 	 * the procedure by giving a unique color (GREEN) to a memory
							 	 * location with more than one taint (thus only logically correct
								 * when there are at most two different tag colors). */
								/* This visualization problem is combinatorial. Ideally when we 
								 * have more than two taint colors, a memory address with multiple
								 * taints should have a unique color depending on what taints are
								 * at this address. We do not attempt to solve this problem. */
								BMP_SetPixelRGB(bmp, i, j, GREEN.r, GREEN.g, GREEN.b);
							}
							if (BMP_GetError() != BMP_OK) {
								printf( "An error has occurred (2): %s (code %d)\n", BMP_GetErrorDescription(), BMP_GetError() );
								BMP_Free(bmp);
								return;
							}
						} else {
							/* White pixel is untainted. */
							BMP_SetPixelRGB(bmp, i, j, WHITE.r, WHITE.g, WHITE.b);
							if (BMP_GetError() != BMP_OK) {
								printf( "An error has occurred (3): %s (code %d)\n", BMP_GetErrorDescription(), BMP_GetError() );
								BMP_Free(bmp);
								return;
							}
						}
						j++;	
					}
				} else {
					for (int y = 0; y < width; y++) {
						BMP_SetPixelRGB(bmp, i, y, WHITE.r, WHITE.g, WHITE.b);
						if (BMP_GetError() != BMP_OK) {
							printf( "An error has occurred (4): %s (code %d)\n", BMP_GetErrorDescription(), BMP_GetError() );
							BMP_Free(bmp);
							return;
						}
					}
				}
				i++;
				address += (1 << 12);
			}
			BMP_WriteFile(bmp, imageFileName);
			if ( BMP_GetError() != BMP_OK ) {
				fprintf(stderr, "BMP error: %s\n", BMP_GetErrorDescription());	
			}
			BMP_Free(bmp);
		} else {
			address += (1 << 10) * (1 << 12);
		}
	}
}

/* This is similar to VisualizeTagMapTable except that we visualize the tag map per page
 * (instead of per page table). Each BMP file then contains less information but is
 * easier to see. BMP file name consists of both table ID and page ID. Color scheme
 * is the same as in VisualizeTagMapTable. */
VOID VisualizeTagMapPage(void)
{
	unsigned long address = 0x0;
	UINT height = sqrt(DIR_PAGE_SZ);
	UINT width = sqrt(DIR_PAGE_SZ);
	for (const auto& table : tag_dir) {
		if (table != NULL) {
			for (const auto& page : *table) {
				if (page != NULL) {
					/* Only visualize if there is at least one tag in the page. */
					bool has_tag = false;
					for (const auto& tag : *page) {
						has_tag |= tag_count(tag);
					}
					if (!has_tag) {
						address += (1 << 12);
						continue;
					}

					/* Prepare to visualize the page. */
					BMP* bmp = BMP_Create(height, width, 32);
					if (BMP_GetError() != BMP_OK) {
						printf("An error has occurred: %s (code %d)\n", BMP_GetErrorDescription(), BMP_GetError());
						BMP_Free(bmp);
						return;
					}
					char imageFileName[50];
					sprintf(imageFileName, "figs/%lu-%lu.bmp", virt2table(address), virt2page(address));

					int i = 0;
					for (const auto& tag : *page) {
						bool has_tag = tag_count(tag);
						if (has_tag) {
							/* A memory location may be tagged with multiple taints. */
							std::vector<size_t> poses = tag.toArray();
							/* If a memort location has only one taint, we visualize it
							 * with its corresponding tag color. */
							if (poses.size() == 1) {
								RGB tag_color = fdmap[(int)poses[0]];
								BMP_SetPixelRGB(bmp, i/height, i%width, tag_color.r, tag_color.g, tag_color.b);
							} else {
								/* Visualizing multiple taint colors can be tricky. We simplify
							 	 * the procedure by giving a unique color (GREEN) to a memory
							 	 * location with more than one taint (thus only logically correct
								 * when there are at most two different tag colors). */
								/* This visualization problem is combinatorial. Ideally when we 
								 * have more than two taint colors, a memory address with multiple
								 * taints should have a unique color depending on what taints are
								 * at this address. We do not attempt to solve this problem. */
								BMP_SetPixelRGB(bmp, i/height, i%width, GREEN.r, GREEN.g, GREEN.b);
							}
							if (BMP_GetError() != BMP_OK) {
								printf( "An error has occurred (2): %s (code %d)\n", BMP_GetErrorDescription(), BMP_GetError() );
								BMP_Free(bmp);
								return;
							}
						} else {
							/* White pixel is untainted. */
							BMP_SetPixelRGB(bmp, i/height, i%width, WHITE.r, WHITE.g, WHITE.b);
							if (BMP_GetError() != BMP_OK) {
								printf( "An error has occurred (3): %s (code %d)\n", BMP_GetErrorDescription(), BMP_GetError() );
								BMP_Free(bmp);
								return;
							}
						}
						i++;	
					}
					BMP_WriteFile(bmp, imageFileName);
					if ( BMP_GetError() != BMP_OK ) {
						fprintf(stderr, "BMP error: %s\n", BMP_GetErrorDescription());	
					}
					BMP_Free(bmp);
				}
				address += (1 << 12);
			}
		} else {
			address += (1 << 10) * (1 << 12);
		}
	}
}

/* Called when a new image is unloaded. 
 * We are printing out the entire tag map. */
VOID ImageUnload(IMG img, VOID *v)
{
	if (IMG_IsMainExecutable(img)) {
		PrintTagMap();
		out << "From Tracked Addresses:\n";
		for (auto addr : addrset) {
			tag_t tag = tagmap_getb(addr);
			out << "[" << StringFromAddrint(addr) << "]: "
			    << tag_sprint(tag)
		    	    << "\n";
		}
		
	}
}

VOID OnExit(INT32 code, VOID *v)
{
	out.setf(ios::showbase);
	out.flush();
	out.close();
}

/* Analysis function: add taint source when open syscall is called. */
#define DEF_SYSCALL_OPEN
#include "syscall_args.h"
template<>
VOID post_open_hook<libdft_tag_ewah>(syscall_ctx_t *ctx)
{
	if (unlikely(_FD < 0)) {
		LOG("ERROR: \t" + std::string(ctx->nr == __NR_creat ? "creat(" : "open(") + _PATHNAME + ", " + decstr(_FLAGS) + ", " + decstr(_MODE) + ") = " + decstr(_FD) + " (" + strerror(errno) + ")\n");
		return;
	}

	/* Resolve fd to full pathname, instead of syscall argument. */
	const std::string fdn = fdname(_FD);

	/* ignore dynamic shared libraries, and directory */
	if (strstr((char *)ctx->arg[SYSCALL_ARG0], DLIB_SUFF) == NULL && strstr((char *)ctx->arg[SYSCALL_ARG0], DLIB_SUFF_ALT) == NULL && !path_isdir(fdn)) {
		out << "OPEN (POST):	"
	    	    << fdn
	    	    << "\n";
	
		fdset.insert((int)ctx->ret);
	}
}
#define UNDEF_SYSCALL_OPEN
#include "syscall_args.h"

/* Analysis function: add taint source when read syscall is called. */
#define DEF_SYSCALL_READ
#include "syscall_args.h"
template<>
VOID post_read_hook<libdft_tag_ewah>(syscall_ctx_t *ctx)
{
	if (unlikely((long)ctx->ret < 0)) {
		LOG("Error reading from fd " + decstr(ctx->arg[SYSCALL_ARG0]) + ": " + strerror(errno) + "\n");
		return;
	}
	/* Define constants for better readability. */
	const size_t nr = ctx->ret;
	const int fd = ctx->arg[SYSCALL_ARG0];
	const LEVEL_BASE::ADDRINT buf = ctx->arg[SYSCALL_ARG1];

	out << "READ:	"
	    << decstr(fd)
	    << " RET: " << nr
	    << " BUF: " << StringFromAddrint(buf)
	    << "\n";

	/* We only set taint source on files that we care. */
	if (fdset.find(fd) != fdset.end()) {
		/* This fd is a taint source, we will give it a color for visualization. 
		 * Note that assigning colors this way may cause collisions. */
		fdmap[fd] = fd_colors[fd % fd_colors.size()];
		/* set tags on read bytes. */
		off_t read_offset_start = 0;
		size_t i = 0;

		/* We do not track stdin/stdout/stderr. 
		 * We comment out the following code for two reasons:
		 * 1. lseek does not work on socket file descriptors. 
		 * 2. We do not need read_offset_start to have byte-specific taint information. */
		/*
		if (!IS_STDFD(fd)) {
			read_offset_start = lseek(fd, 0, SEEK_CUR);
			if (unlikely(read_offset_start < 0)) {
				LOG("ERROR ON L " + decstr(__LINE__) + " lseek on fd " + decstr(fd) + ": " + strerror(errno));
				return;			
			}
			read_offset_start -= nr;
		}
		*/
		
		out << "Taint source from READ: "
		    << decstr(fd)
		    << "\n";

		while (i < nr) {
			tag_t ts_prev = tagmap_getb(buf + i);
			tag_t ts;
			/* Taint set based on file offset. */
			// ts.set(read_offset_start + i);
			/* We instead set taint based on fd. 
			 * Each unique fd has a single unique taint. */
			ts.set(fd);
			tagmap_setb_with_tag(buf+i, ts);
			
			out << "read:tags["
			    << StringFromAddrint(buf+i)
			    << "] : "
			    << tag_sprint(ts_prev)
			    << " -> "
			    << tag_sprint(tagmap_getb(buf+i))
			    << "\n";
			
			i++;

		}
	} else {
		/* clear tags for read bytes. */
		size_t i = 0;
		while (i < nr) {
			tagmap_clrb(buf+i);
			i++;
		}
	}
}
#define UNDEF_SYSCALL_READ
#include "syscall_args.h"

#define DEF_SYSCALL_WRITE
#include "syscall_args.h"
template<>
VOID post_write_hook<libdft_tag_ewah>(syscall_ctx_t *ctx)
{
	/* write is not of interest*/
	if (unlikely(fdset.find(_FD) == fdset.end()))
		return;
	
	/* write was not successful. */
	if (unlikely(_N_WRITTEN < 0)) {
		LOG("ERROR write(" + decstr(_FD) + ", " + StringFromAddrint(_BUF) + ", " + decstr(_COUNT) + ") = " + decstr(_N_WRITTEN) + "lseek on fd " + decstr(_FD) + ": " + strerror(errno) + "\n");
		return;
	}
	
	// off_t write_begin;

	/* calculate the beginning of write. 
	 * we ignore stdout/stderr for now. */
	/* We comment out the following code for the same
	 * reasons as in the read system call case. */
	/*
	if (!IS_STDFD(_FD)) {
		write_begin = lseek(_FD, 0, SEEK_CUR) - _N_WRITTEN;
		if (unlikely(write_begin < 0)) {
			LOG("Error on L" + decstr(__LINE__) + " lseek on fd" + decstr(_FD) + ": " + strerror(errno) + "\n");
			return;
		}
	}
	*/
	
	/* loop through memory locations. */
	for (ssize_t i = 0; i < _N_WRITTEN; i++) {
		tag_t tag = tagmap_getb(_BUF + i);
		out << "write:tags[" << StringFromAddrint(_BUF + i) << "]: "
		    << tag_sprint(tag)
		    << "\n";
	}
}

#define SYS_SOCKET 1 /* socket(2) demultiplex index for socketcall. */
template<>
VOID post_socketcall_hook<libdft_tag_ewah>(syscall_ctx_t *ctx)
{
	unsigned long *args = (unsigned long *)ctx->arg[SYSCALL_ARG1];
	/* Demultiplex socketcall. */
	switch ((int)ctx->arg[SYSCALL_ARG0]) {
		case SYS_SOCKET:
			/* Handling socket system call:
			 * e.g., socket(PF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 12 */
			if (unlikely((long)ctx->ret < 0)) {
				return;
			}
			/* PF_INET and PF_INET6 descriptors are considered. */
			if (likely(args[SYSCALL_ARG0] == PF_INET ||
				   args[SYSCALL_ARG0] == PF_INET6)) {
				/* Add the file descriptor returned by the call. */
				out << "SOCKET:	"
	    	    		    << ctx->ret
	    	    		    << "\n";
	
				fdset.insert((int)ctx->ret);
			}
			/* Finished. */
			break;
		case SYS_ACCEPT:
		case SYS_ACCEPT4:
			/* Handing accept and accept4 system call:
			 * e.g., accept4(12, 0, NULL, SOCK_CLOEXEC|SOCK_NONBLOCK) = 13 */
			if (unlikely((long)ctx->ret < 0)) {
				return;
			}
			/* If the socket argument (returned from socket call) is considered,
			 * the return handle of accept(2) is also considere. */
			if (likely(fdset.find(args[SYSCALL_ARG0]) != fdset.end())) {
				out << "ACCEPT:	"
	    	    		    << ctx->ret
	    	    		    << "\n";

				fdset.insert((int)ctx->ret);
			}
			break;
		default:
			/* Do nothing. */
			return;
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
		result->append("print map		--Print the entire tagmap to the log file.\n");	
		result->append("list			--List all tainted addresses.\n");		
		return TRUE;
	} else if (line == "visual table") {
		VisualizeTagMapTable();
		result->append("Check figs/ for map visualization per table in BMP.\n");
		return TRUE;
	} else if (line == "visual page") {
		VisualizeTagMapPage();
		result->append("Check figs/ for map visualization per page in BMP.\n");
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
	} else if (line == "print map") {
		PrintTagMap();
		result->append("Print tagmap to log file.\n");
		return TRUE;
	} else if (line == "list") {
		ListAll(result);
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

	PIN_AddFiniFunction(OnExit, 0);

	LOG("Initializing libdft...\n");
	/* initialize the core tagging engine */
	if (unlikely(libdft_init() != 0))
		/* failed */
		goto err;

	/* Open Splice log file to ofstream out. */
	out.open(log_path.Value().c_str());

	/* Register ImageLoad function to be called when an image is loaded. We only log the main executable. */
	// IMG_AddInstrumentFunction(ImageLoad, 0);
	// INS_AddInstrumentFunction(Instruction, 0);

	/* Register ImageUnload function to be called when an image is unloaded. */
	IMG_AddUnloadFunction(ImageUnload, 0);

	/* Install taint sources. */
	/* read(2) */
	(void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook<tag_t>);

	/* open(2) */
	if (fs.Value() != 0) {
		(void)syscall_set_post(&syscall_desc[__NR_open], post_open_hook<tag_t>);
	}
	
	/* socket-related taint sources. 
	 * This hook can handle multiple socket-related system calls. */
	if (sk.Value() != 0) {
		(void)syscall_set_post(&syscall_desc[__NR_socketcall], post_socketcall_hook<tag_t>);
	}

	/* Install taint sinks. */
	/* write(2) */
	(void)syscall_set_post(&syscall_desc[__NR_write], post_write_hook<tag_t>);

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

/*
 * Trim whitespace from a line of text.  Leading and trailing whitespace is removed.
 * Any internal whitespace is replaced with a single space (' ') character.
 *
 *  inLine[in]  Input text line.
 *
 * Returns: A string with the whitespace trimmed.
 */
std::string TrimWhitespace(const std::string &inLine)
{
    std::string outLine = inLine;

    bool skipNextSpace = true;
    for (std::string::iterator it = outLine.begin();  it != outLine.end();  ++it)
    {
        if (std::isspace(*it))
        {
            if (skipNextSpace)
            {
                it = outLine.erase(it);
                if (it == outLine.end())
                    break;
            }
            else
            {
                *it = ' ';
                skipNextSpace = true;
            }
        }
        else
        {
            skipNextSpace = false;
        }
    }
    if (!outLine.empty())
    {
        std::string::reverse_iterator it = outLine.rbegin();
        if (std::isspace(*it))
            outLine.erase(outLine.size()-1);
    }
    return outLine;
}
