#include "cheatcall.h"

#include <linux/printk.h>

#include "kvm_emulate.h"
#include "x86.h"


enum CC_COMMAND_ID{
	PHYSICAL_READ,
	PHYSICAL_WRITE,
};

struct CC_COMMAND {
	enum CC_COMMAND_ID id;
	unsigned long from;
	unsigned long to;
	unsigned long size;
};

void dump_cmd(struct CC_COMMAND* cmd){
	pr_err(
		"----CC_COMMAND----\n"
		"id: %u\n"
		"from: %lu\n"
		"to: %lu\n"
		"--------\n\n",
		cmd->id, cmd->from, cmd->to
	);
}


void do_physical_read(struct kvm_vcpu* vcpu, struct CC_COMMAND* cmd)
{
	//TODO: USE PROPER MEMORY ALLCATION
	char* buffer[0x20];
	struct x86_exception exception = {0};
	int ret;

	unsigned long from_pa = cmd->from;
	unsigned long to_va = cmd->to;
	unsigned long size = cmd->size;

	if(
		(from_pa && to_va && size) == 0
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
	return;

}


void do_physical_write(struct kvm_vcpu* vcpu, struct CC_COMMAND* cmd)
{
	//TODO: USE PROPER MEMORY ALLCATION
	char* buffer[0x20];
	struct x86_exception exception = {0};
	int ret;

	unsigned long from_va = cmd->from;
	unsigned long to_pa = cmd->to;
	unsigned long size = cmd->size;

	if(
		(from_va && to_pa && size) == 0
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
		case PHYSICAL_READ:
			do_physical_read(vcpu, &cmd);
			break;
		case PHYSICAL_WRITE:
			do_physical_write(vcpu, &cmd);
			break;
		default:
			break;
	}

	return 1;
}


