#pragma once

#include <linux/kvm_host.h>


#define KVM_HC_CHEATCALL 5577

int cheatcall_do(struct kvm_vcpu* vcpu, unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3);
