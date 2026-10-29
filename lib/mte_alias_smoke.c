#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kasan-enabled.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <asm/memory.h>
#include <asm/mte-kasan.h>
#include <asm/pgtable.h>

#define NOBJECTS 3

static const u8 object_tags[NOBJECTS] = { 5, 6, 7 };

static bool enabled;
static unsigned int probe_alias;
static unsigned int probe_object;
static unsigned int probe_tag;

/*
 * mte_alias_smoke=alias, object, logical_tag
 * alias: 0=A, 1=B
 * object: 0..2
 * logical_tag: 5..7
 */
static int __init mte_alias_setup(char *arg)
{
	unsigned int a, o, t;
	char extra;

	if (sscanf(arg, "%u,%u,%u%c", &a, &o, &t, &extra) != 3)
		return 0;

	if (a > 1 || o >= NOBJECTS || t < 5 || t > 7)
		return 0;

	probe_alias = a;
	probe_object = o;
	probe_tag = t;
	enabled = true;
	return 1;
}
__setup("mte_alias_smoke=", mte_alias_setup);

static u8 *object_ptr(void *alias, unsigned int object, unsigned int tag)
{
	u8 *addr = (u8 *)alias + object * MTE_GRANULE_SIZE;

	return (u8 *)__tag_set(addr, 0xf0 | tag);
}

static void store_allocation_tag(void *ptr)
{
	asm volatile(__MTE_PREAMBLE
			"stg %0, [%0]\n"
			"dsb ish\n"
			:
			: "r" (ptr)
			: "memory");
}

static int __init mte_alias_init(void)
{
	struct page *page;
	void *aliases[2] = { NULL, NULL };
	u8 old_tags[NOBJECTS];
	unsigned int modified = 0;
	unsigned int i;
	u8 *a, *b, *probe;
	phys_addr_t pa;
	int ret = -ENOMEM;

	if (!enabled)
		return 0;

	if (!kasan_hw_tags_enabled()) {
		pr_err("mte alias: hardware-tag KASAN is not active\n");
		return -ENODEV;
	}

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	aliases[0] = vmap(&page, 1, VM_MAP, pgprot_tagged(PAGE_KERNEL));
	aliases[1] = vmap(&page, 1, VM_MAP, pgprot_tagged(PAGE_KERNEL));

	if (!aliases[0] || !aliases[1])
		goto out;

	if (aliases[0] == aliases[1] ||
	    vmalloc_to_page(aliases[0]) != page ||
	    vmalloc_to_page(aliases[1]) != page) {
		pr_err("mte alias: mapping identity check failed\n");
		ret = -EINVAL;
		goto out;
	}

	pa = page_to_phys(page);
	pr_info("mte alias: A=%px B=%px physical=%pa\n", aliases[0], aliases[1], &pa);
	
	for (i = 0; i < NOBJECTS; i++) {
		void *raw = (u8 *)aliases[0] + i * MTE_GRANULE_SIZE;

		old_tags[i] = mte_get_mem_tag(raw);
		store_allocation_tag(object_ptr(aliases[0], i, object_tags[i]));

		modified++;
	}

	for (i = 0; i < NOBJECTS; i++) {
		a = object_ptr(aliases[0], i, object_tags[i]);
		b = object_ptr(aliases[1], i, object_tags[i]);

		WRITE_ONCE(*a, 42 + i);
		if (READ_ONCE(*b) != 42 + i) {
			pr_err("mte alias: A-to-B check failed\n");
			ret = -EIO;
			goto out;
		}
		
		WRITE_ONCE(*b, 52 + i);
		if (READ_ONCE(*a) != 52 + i) {
			pr_err("mte alias: B-to-A check failed\n");
			ret = -EIO;
			goto out;
		}

		pr_info("mte alias: object=%u tag=%u A/B matching access OK\n",
				i, mte_get_mem_tag(b) & 0xf);
	}

	probe = object_ptr(aliases[probe_alias], probe_object, probe_tag);

	pr_info("mte alias: probe alias=%c object=%u logical=%u memory=%u ptr=%px\n",
			'A' + probe_alias, probe_object, probe_tag, object_tags[probe_object], probe);

	WRITE_ONCE(*probe, 99);

	if (probe_tag != object_tags[probe_object]) {
		pr_err("mte alias: ERROR: mismatching-tag store returned\n");
		ret = -EIO;
	} else {
		pr_info("mte alias: matching-tag probe passed\n");
		ret = 0;
	}

out:
	for (i = 0; i < modified; i++) {
		void *raw = (u8 *)aliases[0] + i * MTE_GRANULE_SIZE;

		store_allocation_tag((void *)__tag_set(raw, old_tags[i]));
	}

	if (aliases[1])
		vunmap(aliases[1]);
	if (aliases[0])
		vunmap(aliases[0]);

	__free_page(page);
	return ret;
}
late_initcall(mte_alias_init);
