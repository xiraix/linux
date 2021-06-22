#include "cheatcall.h"

#include "asm/kvm_host.h"
#include <linux/printk.h>
#include <linux/slab.h>

#include "kvm_emulate.h"
#include "kvm_cache_regs.h"
#include "x86.h"

enum CC_COMMAND_ID{
	READ_MSR,
	VIRTUAL_READ,
	VIRTUAL_WRITE,
	PHYSICAL_READ,
	PHYSICAL_WRITE,
};

struct CC_COMMAND {
	enum CC_COMMAND_ID id;
	unsigned long from;
	unsigned long to;
	unsigned long size;
	unsigned long target_cr3;
};

void dump_cmd(struct CC_COMMAND* cmd){
	pr_err(
		"----CC_COMMAND----\n"
		"id: %u\n"
		"from: %lu\n"
		"to: %lu\n"
		"size: %lu\n"
		"target_cr3: %lu\n"
		"--------\n\n",
		cmd->id, cmd->from, cmd->to, cmd->size, cmd->target_cr3
	);
}


void do_read_msr(struct kvm_vcpu* vcpu, struct CC_COMMAND* cmd)
{
	struct x86_exception exception = {0};
	u64 msr_value = 0;
	int ret;

	unsigned long msr_index = cmd->from;
	unsigned long to_va = cmd->to;
	unsigned long size = cmd->size;


	if(
		!msr_index || !to_va || size != sizeof(msr_value) /*8*/
	){
		pr_err("do_test: FAILED - BAD cmd");
		goto out;
	}

	ret = kvm_get_msr(vcpu, msr_index, &msr_value);
	if(ret){
		pr_err("do_test: kvm_get_msr failed with %u\n", ret);
		goto out;
	}

	ret = kvm_read_guest_virt_helper(to_va, &msr_value, sizeof(msr_value), vcpu, 0, &exception);
	if(ret != X86EMUL_CONTINUE){
		pr_err("do_test: kvm_read_guest_virt_helper failed with %u, e: %u\n", ret, exception.error_code);
		goto out;
	}

out:
	return;
	
}


void do_virtual_read(struct kvm_vcpu* vcpu, struct CC_COMMAND* cmd){
	struct x86_exception exception = {0};
	unsigned long caller_cr3 = 0;
	int ret;

	unsigned long from_va = cmd->from;
	unsigned long to_va = cmd->to;
	unsigned long size = cmd->size;
	unsigned long target_cr3 = cmd->target_cr3;

	void* buffer = kmalloc(size, GFP_KERNEL);

	if(
		!from_va || !to_va || !size || !buffer
	){
		pr_err("do_virtual_read: FAILED - BAD cmd");
		goto out;
	}

	//back up original cr3 before switching context
	caller_cr3 = kvm_read_cr3(vcpu);

	//opererate on caller process
	if(!target_cr3){
		pr_err("do_virtual_read: target_cr3 not configured. assuming local\n");
	}
	//operate on remote process
	else{
		pr_err("do_virtual_read: target_cr3 is %lu\n", target_cr3);
		//attach to target process
		kvm_set_cr3(vcpu, target_cr3);
	}

	//---------- now operating inside remote AS ----------

	ret = kvm_read_guest_virt_helper(from_va, buffer, size, vcpu, 0, &exception);
	if(ret != X86EMUL_CONTINUE){
		pr_err("do_virtual_read: FAILED - kvm_read_guest_virt_helper failed with %u\n", ret);
		kvm_set_cr3(vcpu, caller_cr3);
		goto out;
	}

	//--------------------------------------------------

	//re-attach to caller AS. no effect if already attached
	kvm_set_cr3(vcpu, caller_cr3);

	ret = kvm_write_guest_virt_system(vcpu, to_va, buffer, size, &exception);
	if(ret != X86EMUL_CONTINUE){
		pr_err("do_virtual_read: FAILED - kvm_write_guest_virt_system failed with %u", ret);
		goto out;
	}

out:
	if(buffer){
		kfree(buffer);
		return;
	}
}

void do_virtual_write(struct kvm_vcpu* vcpu, struct CC_COMMAND* cmd){
	struct x86_exception exception = {0};
	unsigned long caller_cr3 = 0;
	int ret;

	unsigned long from_va = cmd->from;
	unsigned long to_va = cmd->to;
	unsigned long size = cmd->size;
	unsigned long target_cr3 = cmd->target_cr3;

	void* buffer = kmalloc(size, GFP_KERNEL);

	if(
		!from_va || !to_va || !size || !buffer
	){
		pr_err("do_virtual_write: FAILED - BAD cmd");
		goto out;
	}

	//read memory from local AS to write
	ret = kvm_read_guest_virt_helper(from_va, buffer, size, vcpu, 0, &exception);
	if(ret != X86EMUL_CONTINUE){
		pr_err("do_virtual_write: FAILED - kvm_read_guest_virt_helper failed with %u\n", ret);
		goto out;
	}

	//back up original cr3 before switching context
	caller_cr3 = kvm_read_cr3(vcpu);

	//opererate on caller process
	if(!target_cr3){
		pr_err("do_virtual_write: target_cr3 not configured. assuming local\n");
	}
	//operate on remote process
	else{
		pr_err("do_virtual_write: target_cr3 is %lu\n", target_cr3);
		//attach to target process
		kvm_set_cr3(vcpu, target_cr3);
	}

	//---------- now operating inside remote AS ----------

	ret = kvm_write_guest_virt_system(vcpu, to_va, buffer, size, &exception);
	if(ret != X86EMUL_CONTINUE){
		pr_err("do_virtual_write: FAILED - kvm_write_guest_virt_system failed with %u", ret);
		kvm_set_cr3(vcpu, caller_cr3);
		goto out;
	}

	//--------------------------------------------------

	//re-attach to caller AS. no effect if already attached
	kvm_set_cr3(vcpu, caller_cr3);

out:
	if(buffer){
		kfree(buffer);
		return;
	}
}

void do_physical_read(struct kvm_vcpu* vcpu, struct CC_COMMAND* cmd)
{
	struct x86_exception exception = {0};
	int ret;

	unsigned long from_pa = cmd->from;
	unsigned long to_va = cmd->to;
	unsigned long size = cmd->size;

	void* buffer = kmalloc(size, GFP_KERNEL);

	if(
		!!from_pa || !to_va || !size || !buffer
	){
		pr_err("do_physcal_read: FAILED - BAD cmd");
		goto out;
	}

	ret = kvm_vcpu_read_guest(vcpu, from_pa, buffer, size);
	if(ret != 0){
		pr_err("do_physcal_read: FAILED - kvm_vcpu_read_guest failed with %u", ret);
		goto out;
	}

	kvm_write_guest_virt_system(vcpu, to_va, buffer, size, &exception);
	if(ret !=  X86EMUL_CONTINUE){
		pr_err("do_physcal_read: FAILED - kvm_write_guest_virt_system failed with %u", ret);
		goto out;
	}

out:
	if(buffer){
		kfree(buffer);
	}
	return;

}


void do_physical_write(struct kvm_vcpu* vcpu, struct CC_COMMAND* cmd)
{
	struct x86_exception exception = {0};
	int ret;

	unsigned long from_va = cmd->from;
	unsigned long to_pa = cmd->to;
	unsigned long size = cmd->size;

	void* buffer = kmalloc(size, GFP_KERNEL);

	if(
		!from_va || !to_pa || !size || !buffer
	){
		pr_err("do_physical_write: FAILED - BAD cmd");
		goto out;
	}

	ret = kvm_read_guest_virt(vcpu, from_va, buffer, size, &exception);
	if(ret != X86EMUL_CONTINUE){
		pr_err("do_physical_write: FAILED - Exception code: %u", exception.error_code);
		goto out;
	}

	ret = kvm_vcpu_write_guest(vcpu, to_pa, buffer, size);
	if(ret != 0){
		pr_err("do_physcal_read: FAILED - kvm_vcpu_write_guest failed with %u", ret);
		goto out;
	}

out:
	if(buffer){
		kfree(buffer);
	}
	return;

}

int cheatcall_do(struct kvm_vcpu* vcpu, unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3){
	struct CC_COMMAND cmd = {0};
	struct x86_exception exception = {0};
	int ret = 0;

	pr_err("cheatcall! a0: %lu, a1: %lu, a2: %lu, a3: %lu\n", a0, a1, a2, a3);

	if(!a0){
		pr_err("a0 is NULL!\n");
		return 0;
	}

	ret = kvm_read_guest_virt(vcpu, a0, &cmd, sizeof(cmd), &exception);
	
	//fail condition not tested
	if(ret != X86EMUL_CONTINUE || exception.error_code != 0){
		pr_err(
			"Failed to fetch command struct with\n"
			"\treturn: %u\n"
			"\terror_code: %u\n",
			ret, exception.error_code
		);
	}
	dump_cmd(&cmd);


	switch(cmd.id){
		case READ_MSR:
			do_read_msr(vcpu, &cmd);
			break;
		case VIRTUAL_READ:
			do_virtual_read(vcpu, &cmd);
			break;
		case VIRTUAL_WRITE:
			do_virtual_write(vcpu, &cmd);
			break;
		case PHYSICAL_READ:
			do_physical_read(vcpu, &cmd);
			break;
		case PHYSICAL_WRITE:
			do_physical_write(vcpu, &cmd);
			break;
		default:
			pr_err("Invalid cmd.id %u\n", cmd.id);
			break;
	}

	return 1;
}


