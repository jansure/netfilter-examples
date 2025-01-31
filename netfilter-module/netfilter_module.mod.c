#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_MITIGATION_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x91d91240, "nf_unregister_net_hook" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x50008417, "nf_register_net_hook" },
	{ 0x122c3a7e, "_printk" },
	{ 0xee7ea7f1, "init_net" },
	{ 0x705b90b8, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "133C436AC54D1C9C4BFEF27");
