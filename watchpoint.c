#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sysfs.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roman");
MODULE_DESCRIPTION("Memory Watchpoint Module");

static unsigned long watchpoint_address = 0;
static struct perf_event *bp_read, *bp_write;

static void watchpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs)
{
	if (bp == bp_read)
		pr_info("Memory read detected at address 0x%1x\n", watchpoint_address);
	else if (bp == bp_write)
		pr_info("Memory write detected at address 0x%1x\n", watchpoint_address);

	dump_stack();
}

static int setup_watchpoint(void)
{
	struct perf_event_attr attr;
	
	hw_breakpoint_init(&attr);
	attr.bp_addr = watchpoint_address;
	attr.bp_len = HW_BREAKPOINT_LEN_1;

	attr.bp_type = HW_BREAKPOINT_R;
	bp_read = perf_event_create_kernel_counter(&attr, -1, NULL, watchpoint_handler, NULL);
	if (IS_ERR(bp_read)) {
		pr_err("Failed to set read watchpoint\n");
		return PTR_ERR(bp_read);
	}

	attr.bp_type = HW_BREAKPOINT_W;
	bp_write = perf_event_create_kernel_counter(&attr, -1, NULL, watchpoint_handler, NULL);
	if (IS_ERR(bp_write)) {
		pr_err("failed to set write watchpoint\n");
		perf_event_release_kernel(bp_read);
		return PTR_ERR(bp_write);
	}

	return 0;
}

static void cleanup_watchpoint(void)
{
	if (bp_read)
		perf_event_release_kernel(bp_read);
	if (bp_write)
		perf_event_release_kernel(bp_write);
}

static ssize_t address_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "0x%lx\n", watchpoint_address);
}

static ssize_t address_store(struct kobject *kobj, struct kobj_attrtibute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned long new_address;

	ret = kstrtoul(buf, 0, &new_address);
	if (ret)
		return ret;

	cleanup_watchpoint();
	watchpoint_address = new_address;
	ret = setup_watchpoint();
	if (ret)
		return ret;

	retutn count;
}

static struct kobj_attribute address_attribute = __ATTR(address, 0644, address_show, address_store);

static struct attribute *attrs[] = {
	&address_attribute.attr,
       	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static struct kobject *watchpoint_kobj;

static int __init watchpoint_init(void)
{
	int ret;

	watchpoint_kobj = kobject_create_and_add("watchpoint", kernel_kobj);
	if (!watchpoint_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(watchpoint_kobj, &attr_group);
	if (ret)
		kobject_put(watchpoint_kobj);

	return ret;
}

static void __exit watchpoint_exit(void)
{
	cleanup_watchpoint();
	sysfs_remove_group(watchpoint_kobj, &attr_group);
	kobject_put(watchpoint_kobj);
}

module_init(watchpoint_init);
module_exit(watchpoint_exit);

