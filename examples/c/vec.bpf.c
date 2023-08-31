#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct softirq_entry{
	unsigned long long ignore;
	unsigned int vec;

};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, int);
} cpu_vec_map SEC(".maps");

SEC("tp/irq/softirq_entry")
int handle_tp(struct softirq_entry *ctx){
	int key;
	int val;
	key = bpf_get_smp_processor_id();
	val = ctx->vec;
	bpf_map_update_elem(&cpu_vec_map, &key, &val, BPF_ANY);
	return 0;

};
char LICENSE[] SEC("license") = "Dual BSD/GPL";
