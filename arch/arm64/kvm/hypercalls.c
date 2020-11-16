// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2019 Arm Ltd.

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>

#include <asm/kvm_emulate.h>

#include <kvm/arm_hypercalls.h>
#include <kvm/arm_psci.h>

int kvm_hvc_call_handler(struct kvm_vcpu *vcpu)
{
	u32 func_id = smccc_get_function(vcpu);
	long val = SMCCC_RET_NOT_SUPPORTED;
	u32 feature;
	gpa_t gpa;
	int i; /* GVM porting add */

	kvm_info("%s: vcpu=%p vcpu_idx=%d vcpu_id=%d func_id=%u\n", __func__, vcpu, vcpu->vcpu_idx, vcpu->vcpu_id, func_id);

	/* Will return to userspace */
	/* See https://patchwork.kernel.org/project/linux-arm-kernel/patch/20170808164616.25949-12-james.morse@arm.com/ */
	for (i = 0; i < ARRAY_SIZE(vcpu->run->hypercall.args); i++) {
		vcpu->run->hypercall.args[i] = vcpu_get_reg(vcpu, i);
	}
	vcpu->run->hypercall.longmode = *vcpu_cpsr(vcpu);

	switch (func_id) {
	case ARM_SMCCC_VERSION_FUNC_ID:
	kvm_info("%s: vcpu=%p vcpu_idx=%d vcpu_id=%d func_id=%u version\n", __func__, vcpu, vcpu->vcpu_idx, vcpu->vcpu_id, func_id);
		val = ARM_SMCCC_VERSION_1_1;
		break;
	case ARM_SMCCC_ARCH_FEATURES_FUNC_ID:
	kvm_info("%s: vcpu=%p vcpu_idx=%d vcpu_id=%d func_id=%u arch_features\n", __func__, vcpu, vcpu->vcpu_idx, vcpu->vcpu_id, func_id);
		feature = smccc_get_arg1(vcpu);
		switch (feature) {
		case ARM_SMCCC_ARCH_WORKAROUND_1:
			switch (kvm_arm_harden_branch_predictor()) {
			case KVM_BP_HARDEN_UNKNOWN:
				break;
			case KVM_BP_HARDEN_WA_NEEDED:
				val = SMCCC_RET_SUCCESS;
				break;
			case KVM_BP_HARDEN_NOT_REQUIRED:
				val = SMCCC_RET_NOT_REQUIRED;
				break;
			}
			break;
		case ARM_SMCCC_ARCH_WORKAROUND_2:
			switch (kvm_arm_have_ssbd()) {
			case KVM_SSBD_FORCE_DISABLE:
			case KVM_SSBD_UNKNOWN:
				break;
			case KVM_SSBD_KERNEL:
				val = SMCCC_RET_SUCCESS;
				break;
			case KVM_SSBD_FORCE_ENABLE:
			case KVM_SSBD_MITIGATED:
				val = SMCCC_RET_NOT_REQUIRED;
				break;
			}
			break;
		case ARM_SMCCC_HV_PV_TIME_FEATURES:
			val = SMCCC_RET_SUCCESS;
			break;
		}
		break;
	case ARM_SMCCC_HV_PV_TIME_FEATURES:
	kvm_info("%s: vcpu=%p vcpu_idx=%d vcpu_id=%d func_id=%u hypercall_pv_features\n", __func__, vcpu, vcpu->vcpu_idx, vcpu->vcpu_id, func_id);

		val = kvm_hypercall_pv_features(vcpu);
		break;
	case ARM_SMCCC_HV_PV_TIME_ST:
	kvm_info("%s: vcpu=%p vcpu_idx=%d vcpu_id=%d func_id=%u init_stolen_time\n", __func__, vcpu, vcpu->vcpu_idx, vcpu->vcpu_id, func_id);

		gpa = kvm_init_stolen_time(vcpu);
		if (gpa != GPA_INVALID)
			val = gpa;
		break;
	default:
		return kvm_psci_call(vcpu);
	}

	smccc_set_retval(vcpu, val, 0, 0, 0);
	return 1;
}
