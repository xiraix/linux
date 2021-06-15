#include "cheatcall.h"

#include <linux/printk.h>

int cheatcall_do(struct kvm_vcpu* vcpu, unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3){
	pr_err("cheatcall! a0: %ul, a1: %ul, a2: %ul, a3: %ul", a0, a1, a2, a3);
	return 69;
}


