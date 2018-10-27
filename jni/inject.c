#include <stdio.h>
#include <stdlib.h>
#include <asm/user.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include <errno.h>

#include "sotool.h"

#define AND60_SDK 23

#if defined(__i386__)    
#define pt_regs         user_regs_struct
#endif



#if 0
#define LOG_TAG "INJECT"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)
#define DEBUG_PRINT(format,args...) LOGD(format, ##args)
#else
#define DEBUG_PRINT(format,args...) printf(format, ##args)
#endif

#define CPSR_T_MASK     ( 1u << 5 )
    
const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";
const char *libart_path = "/system/lib/libart.so";

static char dl_module_path[512];
static int sdk_ver = 0;
static unsigned dlopen_ext_offset = 0;

int ptrace_readdata(pid_t pid,  uint8_t *src, uint8_t *buf, size_t size)    
{    
    uint32_t i, j, remain;    
    uint8_t *laddr;    
    
    union u {    
        long val;    
        char chars[sizeof(long)];    
    } d;    
    
    j = size / 4;    
    remain = size % 4;    
    
    laddr = buf;    
    
    for (i = 0; i < j; i ++) {    
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);    
        memcpy(laddr, d.chars, 4);    
        src += 4;    
        laddr += 4;    
    }    
    
    if (remain > 0) {    
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);    
        memcpy(laddr, d.chars, remain);    
    }    
    
    return 0;    
}    
    
int ptrace_writedata(pid_t pid, uint8_t *dest, const uint8_t *data, size_t size)    
{    
    uint32_t i, j, remain;    
    uint8_t *laddr;    
    
    union u {    
        long val;    
        char chars[sizeof(long)];    
    } d;    
    
    j = size / 4;    
    remain = size % 4;    
    
    laddr = (uint8_t*)data;    
    
    for (i = 0; i < j; i ++) {    
        memcpy(d.chars, laddr, 4);    
        int ret = ptrace(PTRACE_POKETEXT, pid, dest, d.val);
        if (ret == -1) {
            DEBUG_PRINT("[ptrace_writedata] poketext failed: %s\n", strerror(errno));
        }
    
        dest  += 4;    
        laddr += 4;    
    }    
    
    if (remain > 0) {    
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
        if (d.val == -1) {
            DEBUG_PRINT("[ptrace_writedata] peektext failed: %s\n", strerror(errno));
        }
        for (i = 0; i < remain; i ++) {
            d.chars[i] = *laddr ++;
        }

        int ret = ptrace(PTRACE_POKETEXT, pid, dest, d.val);
        if (ret == -1) {
            DEBUG_PRINT("[ptrace_writedata] poketext failed: %s\n", strerror(errno));
        }
    }    
    
    return 0;    
}    

int ptrace_setregs(pid_t pid, struct pt_regs * regs);
int ptrace_getregs(pid_t pid, struct pt_regs * regs);
int ptrace_continue(pid_t pid);

#if defined(__arm__)    
int ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs)    
{    
    uint32_t i;    
    for (i = 0; i < num_params && i < 4; i ++) {    
        regs->uregs[i] = params[i];    
    }    
    
    //    
    // push remained params onto stack    
    //    
    if (i < num_params) {    
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;    
        ptrace_writedata(pid, (void *)regs->ARM_sp, (uint8_t *)&params[i], (num_params - i) * sizeof(long));    
    }    
    
    regs->ARM_pc = addr;    
    if (regs->ARM_pc & 1) {    
        /* thumb */    
        regs->ARM_pc &= (~1u);    
        regs->ARM_cpsr |= CPSR_T_MASK;    
    } else {    
        /* arm */    
        regs->ARM_cpsr &= ~CPSR_T_MASK;    
    }    
    
    regs->ARM_lr = 0;
    
    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue(pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}

#elif defined(__i386__)
long ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct user_regs_struct * regs)
{
    regs->esp -= (num_params) * sizeof(long);
    ptrace_writedata(pid, (void *)regs->esp, (uint8_t *)params, (num_params) * sizeof(long));

    long tmp_addr = 0x00;
    regs->esp -= sizeof(long);
    ptrace_writedata(pid, regs->esp, (char *)&tmp_addr, sizeof(tmp_addr));

    regs->eip = addr;

    if (ptrace_setregs(pid, regs) == -1 
            || ptrace_continue( pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}
#else 
#error "Not supported"
#endif

int ptrace_getregs(pid_t pid, struct pt_regs * regs)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_getregs: Can not get register values");
        return -1;
    }

    return 0;
}

int ptrace_setregs(pid_t pid, struct pt_regs * regs)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_setregs: Can not set register values");
        return -1;
    }

    return 0;
}

int ptrace_continue(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        perror("ptrace_cont");
        return -1;
    }

    return 0;
}

int ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
        perror("ptrace_attach");
        return -1;
    }

    int status = 0;
    waitpid(pid, &status , WUNTRACED);

    return 0;
}

int ptrace_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        perror("ptrace_detach");
        return -1;
    }

    return 0;
}

void get_module_path(unsigned long addr, char* module_path) {
    char filename[32];
    snprintf(filename, sizeof(filename), "/proc/self/maps");
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) { 
        DEBUG_PRINT("[get_module_path] open /proc/self/maps failed!\n");
        return;
    }

    char line[512];
    memset(line, 0, 512);
    while (fgets(line, sizeof(line), fp)) {
#if defined(__aarch64__) || defined(__x86_64__)
        char *fmt="%016lx-%016lx %*s %*s %*s %*s %s";
#else
        char *fmt="%x-%x %*s %*s %*s %*s %s";
#endif
        unsigned long b, e;
        sscanf(line, fmt,&b, &e, module_path);
        if (b < addr && e > addr) {
            DEBUG_PRINT("[get_module_path] module_path:%s\n", module_path);
            break;
        }
    }
    fclose(fp);
}

void* get_module_base(pid_t pid, const char* module_name)    
{    
    FILE *fp;    
    long addr = 0;    
    char *pch;    
    char filename[32];    
    char line[1024];    
    
    if (pid < 0) {    
        /* self process */    
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    } else {    
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }    
    
    fp = fopen(filename, "r");    
    
    if (fp != NULL) {    
        while (fgets(line, sizeof(line), fp)) {    
            if (strstr(line, module_name)) {    
                pch = strtok( line, "-" );    
                addr = strtoul( pch, NULL, 16 );    
    
                if (addr == 0x8000)    
                    addr = 0;    
    
                break;    
            }    
        }    
    
        fclose(fp) ;    
    }    
    
    return (void *)addr;    
}    
    
void* get_remote_addr(pid_t target_pid, void* local_addr)
{
    void* local_handle, *remote_handle;

    char module_path[256];
    memset(module_path, 0, 256);
    get_module_path((unsigned long)local_addr, module_path);

    local_handle = get_module_base(-1, module_path);
    remote_handle = get_module_base(target_pid, module_path);

    DEBUG_PRINT("[+] get_remote_addr: local[%p], remote[%p]\n", local_handle, remote_handle);
    void * ret_addr = (void *)((uint32_t)local_addr + (uint32_t)remote_handle - (uint32_t)local_handle);

#if defined(__i386__)
    if (!strcmp(module_path, libc_path)) {
        ret_addr += 2;
    }
#endif
    return ret_addr;
}

int find_pid_of(const char *process_name)
{    
    int id;    
    pid_t pid = -1;    
    DIR* dir;    
    FILE *fp;    
    char filename[32];    
    char cmdline[256];    
    
    struct dirent * entry;    
    
    if (process_name == NULL)    
        return -1;    
    
    dir = opendir("/proc");    
    if (dir == NULL)    
        return -1;    
    
    while((entry = readdir(dir)) != NULL) {    
        id = atoi(entry->d_name);    
        if (id != 0) {    
            sprintf(filename, "/proc/%d/cmdline", id);    
            fp = fopen(filename, "r");    
            if (fp) {    
                fgets(cmdline, sizeof(cmdline), fp);    
                fclose(fp);    
    
                if (strcmp(process_name, cmdline) == 0) {    
                    /* process found */    
                    pid = id;    
                    break;    
                }    
            }    
        }    
    }    
    
    closedir(dir);    
    return pid;    
}    
    
long ptrace_retval(struct pt_regs * regs)    
{    
#if defined(__arm__)    
    return regs->ARM_r0;    
#elif defined(__i386__)    
    return regs->eax;    
#else    
#error "Not supported"    
#endif    
}    
    
long ptrace_ip(struct pt_regs * regs)    
{    
#if defined(__arm__)    
    return regs->ARM_pc;    
#elif defined(__i386__)    
    return regs->eip;    
#else    
#error "Not supported"    
#endif    
}    
    
int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, long * parameters, int param_num, struct pt_regs * regs)
{
	struct pt_regs curreg;
    if (ptrace_getregs(target_pid, &curreg) == -1)
        return -1;
    DEBUG_PRINT("[+] Calling %s in target process, current pc=%ld\n", func_name,  ptrace_ip(&curreg));
    if (ptrace_call(target_pid, (uint32_t)func_addr, parameters, param_num, regs) == -1)
        return -1;

    if (ptrace_getregs(target_pid, regs) == -1)
        return -1;
    DEBUG_PRINT("[+] Target process returned from %s, return value=%lx, pc=%lx \n",
            func_name, ptrace_retval(regs), ptrace_ip(regs));
    return 0;
}

int inject_remote_process(pid_t target_pid, const char *injected_lib, const char *function_name, const char *param, size_t param_size)
{
    int ret = -1;
    void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
    void *local_handle, *remote_handle, *dlhandle;
    uint8_t *map_base = 0;
    uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;

    struct pt_regs regs, original_regs;
    extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, \
        _dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, \
        _saved_cpsr_s, _saved_r0_pc_s;

    uint32_t code_length;
    long parameters[10];
    
    DEBUG_PRINT("[+] Injecting process: %d\n", target_pid);
    
    if (ptrace_attach(target_pid) == -1)
        goto exit;
    
    if (ptrace_getregs(target_pid, &regs) == -1)
        goto exit;
    
    /* save original registers */
    memcpy(&original_regs, &regs, sizeof(regs));
    
    mmap_addr = get_remote_addr(target_pid, (void *)mmap);    
    DEBUG_PRINT("[+] Remote mmap address: %p\n", mmap_addr);    
    
    /* call mmap */    
    parameters[0] = 0;  // addr    
    parameters[1] = 0x1000; // size    
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot    
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags    
    parameters[4] = 0; //fd    
    parameters[5] = 0; //offset    
    
    if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)    
        goto exit;

    map_base = (uint8_t *)ptrace_retval(&regs);
    char* test_str = "111111111111111111111111111111111111";
    ptrace_writedata(target_pid, map_base, (const uint8_t *)test_str, strlen(test_str) + 1);

    uint8_t readbuf[32];
    ptrace_readdata(target_pid, map_base, readbuf, 31);
    readbuf[31] = 0;
    DEBUG_PRINT("[+] read data: %s\n", readbuf);
    
    DEBUG_PRINT("[+] local dlopen=%p, dlsym=%p, dlclose=%p, dlerror=%p\n",
        dlopen, dlsym, dlclose, dlerror);

    dlopen_addr = get_remote_addr(target_pid, (void *)dlopen);
    dlsym_addr = get_remote_addr(target_pid, (void *)dlsym );
    dlclose_addr = get_remote_addr(target_pid, (void *)dlclose);
    dlerror_addr = get_remote_addr(target_pid, (void *)dlerror);
    
    DEBUG_PRINT("[+] Get imports: dlopen: %p, dlsym: %p, dlclose: %p, dlerror: %p\n",
            dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

    DEBUG_PRINT("library path = %s, map_base = %p\n", injected_lib, map_base);
    ptrace_writedata(target_pid, map_base, (const uint8_t *)injected_lib, strlen(injected_lib) + 1);

    if (sdk_ver > AND60_SDK) {
        DEBUG_PRINT("[+] android 7.0+ system, use dlopen_ext\n");
        void* target_linker_base = get_module_base(target_pid, linker_path);
        void* target_dlopen_ext_addr = (void*)((unsigned long)target_linker_base + dlopen_ext_offset);
        DEBUG_PRINT("[+] target_dlopen_ext_addr addr: %p\n", target_dlopen_ext_addr);
        void* target_libart_base = get_module_base(target_pid, libart_path);
        unsigned long target_caller_addr = (unsigned long)target_libart_base + 0x2000;
        DEBUG_PRINT("[+] target_caller_addr addr: %p\n", (void*)target_caller_addr);

        parameters[0] = (long)map_base;
        parameters[1] = RTLD_NOW;
        parameters[2] = 0;
        parameters[3] = target_caller_addr;
    
        if (ptrace_call_wrapper(target_pid, "dlopen_ext", target_dlopen_ext_addr, 
                parameters, 4, &regs) == -1)
            goto exit;
    }
    else {
        parameters[0] = (long)map_base;
        parameters[1] = RTLD_NOW| RTLD_GLOBAL;
    
        if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
            goto exit;
    }

    void* sohandle = (void*)ptrace_retval(&regs);
    
#define FUNCTION_NAME_ADDR_OFFSET 0x100
    ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET, (const uint8_t *)function_name, strlen(function_name) + 1);
    parameters[0] = (long)sohandle;
    parameters[1] = (long)(map_base + FUNCTION_NAME_ADDR_OFFSET);
    
    if (ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)    
        goto exit;    
    
    void* hook_entry_addr = (void*)ptrace_retval(&regs);    
    DEBUG_PRINT("hook_entry_addr = %p\n", hook_entry_addr);    
    
#define FUNCTION_PARAM_ADDR_OFFSET      0x200    
    ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET, (uint8_t*)param, strlen(param) + 1);    
    parameters[0] = (long)(map_base + FUNCTION_PARAM_ADDR_OFFSET);


    // if (ptrace_call_wrapper(target_pid, "hook_entry", hook_entry_addr, parameters, 1, &regs) == -1)    
    //     goto exit;        

    printf("Press enter to dlclose and detach\n");    
    //getchar();    
    parameters[0] = (long)sohandle;       
    
    if (ptrace_call_wrapper(target_pid, "dlclose", dlclose, parameters, 1, &regs) == -1)    
        goto exit;    
    
    /* restore */    
    ptrace_setregs(target_pid, &original_regs);    
    ptrace_detach(target_pid);    
    ret = 0;    
    
exit:    
    return ret;    
}

static void init_sdk_ver(){
    char value[32] = {0};

    int len = __system_property_get("ro.build.version.sdk", value);
    if (len <= 0) {
        DEBUG_PRINT("[init_sdk_ver] read ro.build.version.sdk error!");
        return;
    }

    sdk_ver = atoi(value);
    DEBUG_PRINT("[init_sdk_ver] ro.build.version.sdk: %d\n", sdk_ver);
}

static void init_dlopen_ext_offset() {
    FILE *fp = NULL;
    if (!(fp = fopen(linker_path, "rb")))  {
        DEBUG_PRINT("[init_dlopen_ext_offset]Unable to open %s\n", linker_path);
        return;
    }

    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buffer = (char*)malloc(size);
    if (fread(buffer, 1, size, fp) != size) {
        DEBUG_PRINT("fread error\n");
        return;
    }
    fclose(fp);

    unsigned long symstr_off = 0, symtab_off = 0, symtab_size = 0;
    unsigned long symtab_entsize = 0, symtab_count = 0;
    const elf_header_t* eh  = (elf_header_t*)buffer;
    const elf_sheader_t* esh = (elf_sheader_t*)(buffer + eh->shoff);
    char* section_str = esh[eh->shstrndx].sh_offset + buffer;

    for (int i = 0; i < eh->shnum; i++) {
        char* sname = esh[i].sh_name + section_str;
        if (strcmp(sname, ".symtab") == 0) {
            symtab_off = esh[i].sh_offset; 
            symtab_size = esh[i].sh_size;
            symtab_entsize = esh[i].sh_entsize;
            symtab_count = symtab_size / symtab_entsize;
            DEBUG_PRINT("[init_dlopen_ext_offset]: symtab offset = %lx, count=%lx, index= %d\n", 
                symtab_off, symtab_count, i);
        }
        if (strcmp(sname, ".strtab") == 0) {
            symstr_off = esh[i].sh_offset;
            DEBUG_PRINT("[init_dlopen_ext_offset] symstr offset = %lx, index = %d\n", symstr_off, i);
        }

    }

    if(!symtab_off) {
        DEBUG_PRINT("[init_dlopen_ext_offset] can't find symtab from sections\n");
    }

    elf_sym_t* edt = (elf_sym_t*)(buffer + symtab_off);

    const char* name_dlopen_ext_N = "__dl__ZL10dlopen_extPKciPK17android_dlextinfoPv";
    const char* name_dlopen_ext_O = "__dl__ZL10dlopen_extPKciPK17android_dlextinfoPKv";
    const char* name_dlopen_ext_P = "__dl___loader_android_dlopen_ext";

    for(int i = 0 ; i < symtab_count; i++) {
        uint8_t st_type = ELF32_ST_TYPE(edt[i].info);
        char* st_name = buffer + symstr_off + edt[i].name;
        // DEBUG_PRINT("[init_dlopen_ext_offset] walk sym name:%s, value:%x\n", st_name, edt[i].value);
        if (st_type == STT_FUNC && edt[i].size) {
            if(strcmp(st_name, name_dlopen_ext_N) == 0) {
                dlopen_ext_offset = edt[i].value;
                DEBUG_PRINT("[init_dlopen_ext_offset] find dlopen_ext_N: %x\n", dlopen_ext_offset);
                break;
            }
            else if (strcmp(st_name, name_dlopen_ext_O) == 0) {
                dlopen_ext_offset = edt[i].value;
                DEBUG_PRINT("[init_dlopen_ext_offset] find dlopen_ext_O: %x\n", dlopen_ext_offset);
                break;
            }
            else if (strcmp(st_name, name_dlopen_ext_P) == 0) {
                dlopen_ext_offset = edt[i].value;
                DEBUG_PRINT("[init_dlopen_ext_offset] find dlopen_ext_P: %x\n", dlopen_ext_offset);
                break;
            }
        }
    }

    free(buffer);
}

int main(int argc, char** argv) {    
    if (argc < 3) {
        DEBUG_PRINT("[main] usage: ./inject {pid} {libpath}");
    }
    pid_t target_pid = atoi(argv[1]);
    char* injected_lib = argv[2];
    DEBUG_PRINT("[main] target_pid:%d, libpath:%s\n", target_pid, injected_lib);

    init_sdk_ver();
    if (sdk_ver > AND60_SDK) {
        init_dlopen_ext_offset();
        if (dlopen_ext_offset == 0) {
            DEBUG_PRINT("[main] can't locate dlopen_ext\n");
            return 1;
        }
    }

    char* param = "I'm parameter!";
    inject_remote_process(target_pid, injected_lib, "hook_entry", param, strlen(param));
    return 0;  
}