#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <asm/memory.h>
#include <asm/pgtable.h>
#include <asm/set_memory.h>

// 0: disabled
// 1: test valid alias
// 2: also access invalid alias
static int alias_mode;

static int __init alias_smoke_setup(char *arg)
{
	if (!strcmp(arg, "good"))
		alias_mode = 1;
	else if (!strcmp(arg, "bad"))
		alias_mode = 2;
	else
		return 0;

	return 1;
}

__setup("alias_smoke=", alias_smoke_setup);

static int __init alias_smoke_init(void)
{
	struct page *page;
	u8 *a = NULL, *b = NULL;
	phys_addr_t pa;
	bool b_invalid = false;
	int ret = -ENOMEM;
	int restore_ret;

	if (!alias_mode)
		return 0;

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	a = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	b = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!a || !b)
		goto out;

	if (a == b || vmalloc_to_page(a) != page || vmalloc_to_page(b) != page) {
		pr_err("alias smoke: mapping identity check failed\n");
		ret = -EINVAL;
		goto out;
	}

	pa = page_to_phys(page);
	pr_info("alias smoke: A=%px B=%px physical=%pa\n", a, b, &pa);


	WRITE_ONCE(*a, 42);
	if (READ_ONCE(*b) != 42) {
		pr_err("alias smoke: A-to-B readback failed\n");
		ret = -EIO;
		goto out;
	}
	WRITE_ONCE(*b, 43);
	if (READ_ONCE(*a) != 43) {
		pr_err("alias smoke: B-to-A readback failed\n");
		ret = -EIO;
		goto out;
	}
	pr_info("alias smoke: both aliases share data\n");

	ret = set_memory_valid((unsigned long)b, 1, 0);
	if (ret) {
		pr_err("alias smoke: invalidation failed: %d\n", ret);
		goto out;
	}
	b_invalid = true;

	WRITE_ONCE(*a, 77);
	if (READ_ONCE(*a) != 77) {
		pr_err("alias smoke: valid alias A failed\n");
		ret = -EIO;
		goto out;
	}
	pr_info("alias smoke: B invalid; A store/read still OK\n");

	if (alias_mode == 2) {
		pr_info("alias smoke: next store through B should fault\n");
		WRITE_ONCE(*b, 99);

		pr_err("alias smoke: ERROR: invalid alias B was accessible\n");
		ret = -EIO;
	} else {
		pr_info("alias smoke: good mode passed\n");
	}

out:
	if (b_invalid) {
		restore_ret = set_memory_valid((unsigned long)b, 1, 1);
		if (restore_ret)
			panic("alias smoke: restore failed: %d", restore_ret);
	}

	if (b) 
		vunmap(b);
	if (a)
		vunmap(a);

	__free_page(page);
	return ret;
}
late_initcall(alias_smoke_init);
