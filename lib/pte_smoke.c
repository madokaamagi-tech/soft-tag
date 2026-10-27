#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kasan.h>
#include <linux/kasan-enabled.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

#include <asm/memory.h>
#include <asm/mte-kasan.h>
#include <asm/set_memory.h>

// 0: disabled
// 1: matching tag only
// 2: also test mismatching tag
static int smoke_mode;

static int __init mte_smoke_setup(char *arg)
{
	if (!strcmp(arg,"good"))
		smoke_mode = 1;
	else if (!strcmp(arg, "bad"))
		smoke_mode = 2;
	else if (!strcmp(arg, "pte"))
		smoke_mode = 3;
	else
		return 0;

	return 1;
}

__setup("mte_smoke=", mte_smoke_setup);

// Copy the pointer's logical tag into one 16-byte memory granule.
static void smoke_stg(void *ptr)
{
	asm volatile(__MTE_PREAMBLE
			"stg %0, [%0]\n"
			"dsb ish\n"
			:
			: "r" (ptr)
			: "memory");
}

static int drop_pte_valid(void *p)
{
	unsigned long addr = (unsigned long)kasan_reset_tag(p);

	if (!PAGE_ALIGNED(addr))
		return -EINVAL;

	// clear PTE_VALID and flush the kernel TLB
	return set_memory_valid(addr, 1, 0);
}

static int __init pte_smoke_init(void)
{
	u8 *p;
	unsigned long addr;
	int ret;

	p = vmalloc(PAGE_SIZE);
	if (!p)
		return -ENOMEM;

	addr = (unsigned long)kasan_reset_tag(p);

	WRITE_ONCE(*p, 42);
	if (READ_ONCE(*p) != 42) {
		pr_err("pte_smoke: initial readback failed\n");
		vfree(p);
		return -EIO;
	}

	pr_info("pte smoke: mapped store/read OK, p=%px va=%#lx\n", p, addr);

	ret = drop_pte_valid(p);
	if (ret) {
		pr_err("pte smoke: invalidation failed: %d\n", ret);
		vfree(p);
		return ret;
	}

	pr_info("pte smoke: PTE_VALID cleared and TLB flushed\n");
	pr_info("pte smoke: next store should cause a translation fault\n");

	WRITE_ONCE(*p, 99);

	pr_err("pte smoke: ERROR: store through invalid mapping returned\n");

	ret = set_memory_valid(addr, 1, 1);
	if (ret)
		panic("pte smoke: failed to restore mapping: %d", ret);

	vfree(p);
	return -EIO;
}



static int __init mte_smoke_init(void)
{
	u8 *p, *good, *bad;
	int ret = 0;

	if (!smoke_mode)
		return 0;

	if (smoke_mode == 3)
		return pte_smoke_init();

	if (!kasan_hw_tags_enabled()) {
		pr_err("mte smoke: hardware-tag KASAN is not active\n");
		return -ENODEV;
	}

	p = kmalloc(MTE_GRANULE_SIZE, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	good = (u8 *)__tag_set(p, 0xf5);
	bad = (u8 *)__tag_set(p, 0xf6);

	pr_info("mte smoke: p=%px good=%px bad=%px\n", p, good, bad);

	smoke_stg(good);
	pr_info("mte smoke: allocation tag=%x\n", mte_get_mem_tag(good) & 0xf);

	WRITE_ONCE(*good, 42);
	if (READ_ONCE(*good) != 42) {
		pr_err("mte smoke: readback failed\n");
		ret = -EIO;
		goto out;
	}
	pr_info("mte smoke: matching-tag store/read OK\n");

	if (smoke_mode == 2) {
		pr_info("mte smoke: next store uses tag 6; expect fault\n");
		WRITE_ONCE(*bad, 99);
		pr_err("mte smoke: bad store returned; inspect KASAN log\n");
		ret = -EIO;
	}

// Restore the allocator's original tag before freeing. 
out:
	smoke_stg(p);
	kfree(p);
	return ret;
}
late_initcall(mte_smoke_init);

