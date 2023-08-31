#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "vec.skel.h"

struct softirq_entry{
	unsigned long long ignore;
	unsigned int vec;

};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
  int _vec;
  struct vec_bpf *skel;
  int err;

  int key = 0;
  libbpf_set_print(libbpf_print_fn);
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  skel = vec_bpf__open();

  if (!skel) {

    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;

  }

  err = vec_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = vec_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
  while(!exiting){
    bpf_map__lookup_elem((skel->maps.cpu_vec_map), &key, sizeof(int), &_vec, sizeof(int), BPF_ANY);
    printf("vec on cpu0 is %d \n ",_vec);
  }
  
cleanup:
	/* Clean up */
	vec_bpf__destroy(skel);

	return err < 0 ? -err : 0;
};
