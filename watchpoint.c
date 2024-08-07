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

