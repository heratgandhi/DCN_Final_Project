#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xa8c16cf3, "module_layout" },
	{ 0x6f2e6f37, "remove_proc_entry" },
	{ 0x4b0560d1, "nf_unregister_hook" },
	{ 0x409e0376, "nf_register_hook" },
	{ 0x77ba54e8, "create_proc_entry" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x4f6b400b, "_copy_from_user" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0x37a0cba, "kfree" },
	{ 0x783c7933, "kmem_cache_alloc_trace" },
	{ 0x352091e6, "kmalloc_caches" },
	{ 0x69acdf38, "memcpy" },
	{ 0x27e1a049, "printk" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x91715312, "sprintf" },
	{ 0x20c55ae0, "sscanf" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "5F5D87321BC21DF1C22505D");
