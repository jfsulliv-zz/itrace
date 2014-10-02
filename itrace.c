#include <udis86.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

/* 
 * itrace(1) : Trace the instuctions executed by a running process
 *      James Sullivan <sullivan.james.f@gmail.com>
 *      10095183
 */

#define PID_MIN     1
#define PID_MAX     32768

#define verbose(format, ...) do {           \
    if (VERBOSE_MODE)                       \
        printf(format, ##__VA_ARGS__);      \
    } while(0)

#if __x86_64__
    #define IP_REG rip
    #define print_addr(format, ...) do {            \
        printf(format "0x%016Lx",                   \
                (unsigned long long)__VA_ARGS__);   \
    } while(0)
#else
    #define IP_REG eip
    #define print_addr(format, ...) do {                        \
        printf(format "0x%08x", (unsigned int)__VA_ARGS__);     \
    } while(0)
#endif

int VERBOSE_MODE = 0;
static int MAX_INST_SIZE = 16;

int print_bytes(unsigned char *buf, size_t num)
{
    int i = 0;
    printf("0x");
    for(i = 0; i < num; i++){
        printf("%02x",(unsigned int)buf[i]);
    }
    printf("\n");
    
    return 0;
}

int print_usage(char *name)
{
    printf("Usage: %s -p PID [-v -h]\n",name);
    return 0;
}

/*
 * Read a word at 'addr' in the process addresss space of PID,
 * and write it to at 'dest'.
 *
 * Returns 0 on success, and 1 on failure.
 */
int read_word(pid_t pid, void *addr, unsigned long *dest)
{
    if(!pid) 
        return 1;

    errno = 0;
    unsigned long ret;
    /* Read a word from the child address space */
    ret = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if(errno) 
        return 1;

    *dest = ret;
    return 0;
}

/*
 * Reads num bytes from the process address space at addr, and 
 * writes them to dest.
 * 
 * Returns 0 on success, and 1 on failure.
 */
int read_from_process(pid_t pid, void *addr, void *dest, size_t num)
{
    if(!pid || !dest)
        return 1;

    int dif, word_size, i;

    word_size = sizeof(void *);
    dif = num % word_size; /* leftover bytes */

    /* Read word-by-word until num bytes are read */
    for(i = 0; i < num; i += word_size) {
        if(read_word(pid, addr+i, (unsigned long *)(dest+i))) {
            memset(dest,0,num);
            return 1;    
        }
    }

    /* Zero the extra bytes */
    if(dif) {
        char *end = (char *)dest + i - word_size;
        memset(end,0,dif);
    }

    return 0;
}

/*
 * Attempts to attach to PID and halt its execution.
 * Returns 0 on success and 1 on failure.
 */
int attach_to_pid(pid_t pid)
{
    if(pid < PID_MIN || pid > PID_MAX) {
        fprintf(stderr, "Invalid PID \"%d\"\n",pid);
        return 1;
    }

    verbose("Attaching to %d\n",(int)pid);

    errno = 0;
    /* Attempt to attach to PID */
    if(ptrace(PTRACE_ATTACH,pid,0,0)) {
        fprintf(stderr, 
                "Failed to attach to Process %d ",
                pid);
        switch(errno){
            case 3:
                fprintf(stderr,"(No such process)\n");
                break;
            default:
                fprintf(stderr,"(Operation not permitted)\n");
        }
        return 1;
    }

    /* Halt execution of the child process */
    kill(pid, SIGSTOP);
    verbose("Stopped %d\n", (int)pid);

    return 0;
}

/*
 * Single steps the process process.
 * Returns 0 on success, and 1 if the process could not be stepped
 *  (ie, it finished execution or was killed prematurely) 
 */
int step_process(pid_t pid)
{
    errno = 0;
    if(ptrace(PTRACE_SINGLESTEP,pid,0,0)) {
        verbose("Failed to single step process %u\n",pid);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv, char **envp)
{
    if(argc < 3) {
        print_usage(argv[0]);
        exit(1);
    }
    
    /* Parse arguments */
    opterr = 0;
    char c;
    char *apid;
    apid = NULL;
    while((c = getopt(argc, argv, "p:hv")) != -1) {
        switch(c) {
            case 'p':
                apid = optarg;
                break;
            case 'v':
                VERBOSE_MODE = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }
    if(!apid) {
        print_usage(argv[0]);
        exit(1);
    }

    /* Try to attach to PID */
    pid_t pid = atoi(apid);
    if(attach_to_pid(pid))
        exit(1);
    verbose("Attached to pid %u\n",pid);

    /* Get the register record */
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS,pid,0,&regs);

    void *curr_inst;
    unsigned char inst_buf[MAX_INST_SIZE];
    
    /* Setup Disassembler object */
    ud_t ud_obj;
    ud_init(&ud_obj);
    ud_set_syntax(&ud_obj, UD_SYN_INTEL); /* Sane syntax */
    ud_set_pc(&ud_obj, regs.IP_REG); /* Set EIP to current value */
    verbose("Initialised disassembler\n");

    int w_val;
    while(1) {
        /* Get the instruction to be executed */
        ptrace(PTRACE_GETREGS,pid,0,&regs);
        curr_inst = (void *)regs.IP_REG;

        /* Single-step the child process */
        step_process(pid);
        /* Check for termination, update register record */
        wait(&w_val);
        if(WIFEXITED(w_val)) {
            printf("Process %d exited normally\n",pid);
            break;
        } else if(WIFSIGNALED(w_val)) {
            printf("Process %d was killed by signal %d\n",pid,w_val);
            break;
        }

        /* Set the Disassembler input buffer and read MAX_INSTR_SIZE
            bytes from the address in child's EIP */
        memset(inst_buf,0,MAX_INST_SIZE);
        ud_set_input_buffer(&ud_obj, inst_buf, MAX_INST_SIZE);

        if(!read_from_process(pid, curr_inst, inst_buf, 
                 MAX_INST_SIZE)){
            print_addr("",curr_inst);
            printf(": \t");

            /* Attempt to disassemble a single instruction at EIP */
            if(ud_disassemble(&ud_obj)) {
                printf("%s\n",ud_insn_asm(&ud_obj)); 
            } else 
                printf("Failed Disassembly\n"); 
        }
    }

    return 0;    
}
