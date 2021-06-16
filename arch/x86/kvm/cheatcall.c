#include "cheatcall.h"

#include <linux/printk.h>

int cheatcall_do(struct kvm_vcpu* vcpu, unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3){
	pr_err("cheatcall! a0: %lu, a1: %lu, a2: %lu, a3: %lu\n", a0, a1, a2, a3);
	return 69;
}


