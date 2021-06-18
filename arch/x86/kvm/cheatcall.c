#include "cheatcall.h"

#include <linux/printk.h>

#include "kvm_emulate.h"
#include "x86.h"


enum CC_COMMAND_ID{
	PRINT_PHYSICAL_QWORD,
	PRINT_VIRTUAL_QWORD,
};

struct CC_COMMAND {
	enum CC_COMMAND_ID id;
	unsigned long from;
	unsigned long to;
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
		default:
			break;
	}

	return 1;
}


