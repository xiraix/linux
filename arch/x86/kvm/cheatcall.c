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

void dump_exception(struct x86_exception* e){
	pr_err(
		"---Exception---\n"
		"vector: %hhu\n"
		"error_code_valid: %hhu\n"
		"error_code: %hu\n"
		"nested_page_fault: %hhu\n"
		"address: %llu\n"
		"async_page_fault: %hhu\n"
		"--------------\n",
		e->vector, e->error_code, e->error_code_valid, e->nested_page_fault, e->address, e->async_page_fault
	);
}

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


static int try_read_guest_virt(struct kvm_vcpu* vcpu, unsigned long gva_from, void* hva_to, unsigned long size, unsigned long target_cr3){
	struct x86_exception exception = {0};
	int ret;
	
	unsigned long caller_cr3 = kvm_read_cr3(vcpu);
	target_cr3 = target_cr3 ? target_cr3 : caller_cr3;

	kvm_set_cr3(vcpu, target_cr3);


	ret = kvm_read_guest_virt(vcpu, gva_from, hva_to, size, &exception);
	if(ret != X86EMUL_CONTINUE){
		pr_err("do_virtual_read: FAILED - kvm_read_guest_virt failed with %u\n", ret);
		dump_exception(&exception);
		memset(&exception, 0, sizeof(struct x86_exception));
		ret = kvm_read_guest_virt_helper(gva_from, hva_to, size, vcpu, 0, &exception);
		if(ret != X86EMUL_CONTINUE){
			pr_err("do_virtual_read: FAILED - kvm_read_guest_virt_helper failed with %u\n", ret);
			dump_exception(&exception);
		}
	}

	kvm_set_cr3(vcpu, caller_cr3);

	return ret;

}

static int try_write_guest_virt(struct kvm_vcpu* vcpu, void* hva_from, unsigned long gva_to, unsigned long size, unsigned long target_cr3){
	struct x86_exception exception = {0};
	int ret;

	unsigned long caller_cr3 = kvm_read_cr3(vcpu);
	target_cr3 = target_cr3 ? target_cr3 : caller_cr3;


	kvm_set_cr3(vcpu, target_cr3);


	ret = kvm_write_guest_virt_helper(gva_to, hva_from, size, vcpu, 0, &exception);
	if(ret != X86EMUL_CONTINUE){
		pr_err("do_virtual_read: FAILED - kvm_write_guest_virt_helper failed with %u", ret);
		dump_exception(&exception);
		memset(&exception, 0, sizeof(struct x86_exception));
		ret = kvm_write_guest_virt_system(vcpu, gva_to, hva_from, size, &exception);
		if(ret != X86EMUL_CONTINUE){
			pr_err("do_virtual_read: FAILED - kvm_write_guest_virt_system failed with %u", ret);
			dump_exception(&exception);
		}
	}

	kvm_set_cr3(vcpu, caller_cr3);

	return ret;
}

void do_read_msr(struct kvm_vcpu* vcpu, struct CC_COMMAND* cmd)
{
	u64 msr_value = 0;
	int ret;
	unsigned long temp0;

	unsigned long msr_index = cmd->from;
	unsigned long to_va = cmd->to;
	unsigned long size = cmd->size;


	if(
		!msr_index || !to_va || size != sizeof(msr_value) /*8*/
	){
		pr_err("do_read_msr: FAILED - BAD cmd");
		goto out;
	}

	ret = try_read_guest_virt(vcpu, to_va, &temp0, 8, 0);
	pr_err("msr buffer to_va: %lu, ret: %u\n", temp0, ret);

	ret = kvm_get_msr(vcpu, msr_index, &msr_value);
	if(ret){
		pr_err("do_read_msr: kvm_get_msr failed with %u\n", ret);
		goto out;
	}

	ret = try_write_guest_virt(vcpu, &msr_value, to_va, sizeof(msr_value), 0);
	if(ret != X86EMUL_CONTINUE){
		goto out;
	}

out:
	return;
	
}


void do_virtual_read(struct kvm_vcpu* vcpu, struct CC_COMMAND* cmd){
	int ret;

	unsigned long from_va = cmd->from;
	unsigned long to_va = cmd->to;
	unsigned long size = cmd->size;
	unsigned long target_cr3 = cmd->target_cr3 ;

	void* buffer = kmalloc(size, GFP_KERNEL);

	if(
		!from_va || !to_va || !size || !buffer
	){
		pr_err("do_virtual_read: FAILED - BAD cmd");
		goto out;
	}

	//---------- now operating inside remote AS ----------

	ret = try_read_guest_virt(vcpu, from_va, buffer, size, target_cr3);
	if(ret != X86EMUL_CONTINUE){
		goto out;
	}

	//--------------------------------------------------

	ret = try_write_guest_virt(vcpu, buffer, to_va, size, 0);
	if(ret != X86EMUL_CONTINUE){
		goto out;
	}

out:
	if(buffer){
		kfree(buffer);
		return;
	}
}

void do_virtual_write(struct kvm_vcpu* vcpu, struct CC_COMMAND* cmd){
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
	ret = try_read_guest_virt(vcpu, from_va, buffer, size, 0);
	if(ret != X86EMUL_CONTINUE){
		goto out;
	}

	//---------- now operating inside remote AS ----------

	ret = try_write_guest_virt(vcpu, buffer, to_va, size, target_cr3);
	if(ret != X86EMUL_CONTINUE){
		goto out;
	}

	//--------------------------------------------------

out:
	if(buffer){
		kfree(buffer);
		return;
	}
}

void do_physical_read(struct kvm_vcpu* vcpu, struct CC_COMMAND* cmd)
{
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

	try_write_guest_virt(vcpu, buffer, to_va, size, 0);
	if(ret !=  X86EMUL_CONTINUE){
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

	ret = try_read_guest_virt(vcpu, from_va, buffer, size, 0);
	if(ret != X86EMUL_CONTINUE){
		pr_err("do_physical_write: FAILED - with: %u", ret);
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
	int ret = 0;

	pr_err("cheatcall! a0: %lu, a1: %lu, a2: %lu, a3: %lu\n", a0, a1, a2, a3);

	if(!a0){
		pr_err("a0 is NULL!\n");
		return 0;
	}

	ret = try_read_guest_virt(vcpu, a0, &cmd, sizeof(cmd), 0);
	
	//fail condition not tested
	if(ret != X86EMUL_CONTINUE){
		pr_err(
			"Failed to fetch command struct with\n"
			"\treturn: %u\n",
			ret
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


