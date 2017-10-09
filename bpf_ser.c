#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "libbpf.h"

#define LOG_BUF_SIZE 1024
char bpf_log_buf[LOG_BUF_SIZE];

int bpf_create_map(enum bpf_map_type map_type, unsigned int key_size, unsigned int value_size, unsigned int max_entries);
int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns, int prog_len, const char *license);
int bpf_lookup_elem(int fd, const void *key, void *value);
int bpf_update_elem(int fd, const void *key, const void *value, uint64_t flags);
int bpf_get_next_key(int fd, void *key, void *next_key);

unsigned str_length(const char str[]);
void rev_string(char str[]); 
  
static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}


int main(int argc, char ** argv)
{
  int sd;
  struct sockaddr_in addr;

  struct pkt_data {
    int type;
    char key[4];
    int value;
  };
  
  socklen_t sin_size;
  struct sockaddr_in from_addr;
  struct pkt_data pkt;

  char buf[2048];
  int buf2;

  int map_fd, map_fd2, prog_fd;
  int key;
  int  value;

  if ((map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), 3)) < 0) {
    perror("bpf_create_map");
    return -1;
  }

  if ((map_fd2 = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(pkt.key), 1)) < 0) {
    perror("bpf_create_map");
    return -1;
  }

  
  int key2= 2;
  int value2 = 30;
  if ((bpf_update_elem(map_fd, &key2, &value2, BPF_ANY)) < 0) {
    perror("bpf_update_elem");
    return -1;
  }

  
  struct bpf_insn prog[] = {
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
    BPF_LD_ABS(BPF_B, 8),

    BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 1, 12),
    /*BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 1),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
    BPF_ST_MEM(BPF_DW, BPF_REG_10, -16, 2222),
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -16),
    BPF_MOV64_IMM(BPF_REG_4, BPF_ANY),
    BPF_LD_MAP_FD(BPF_REG_1, map_fd),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),
    */
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
    BPF_LD_ABS(BPF_W, 12),
    BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -16),
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -16),
    BPF_MOV64_IMM(BPF_REG_4, BPF_ANY),
    BPF_LD_MAP_FD(BPF_REG_1, map_fd2),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),
    

    BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
    
    BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, -16),
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -16),
    BPF_MOV64_IMM(BPF_REG_4, BPF_ANY),
    BPF_LD_MAP_FD(BPF_REG_1, map_fd),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),
    
    BPF_EXIT_INSN(),
  };
    

  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    return -1;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = htons(22222);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return -1;
  }


  int flag = 0;
  while (flag != 3) {
    if(recvfrom(sd, &pkt, sizeof(struct pkt_data), 0, (struct sockaddr *)&from_addr, &sin_size) < 0) {
      perror("recvfrom");
      return -1;
    }
    flag = pkt.type;
  }
  printf("start!\n");
  
  
  if ((prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog), "GPL")) < 0) {
    printf("bpf_prog_load() err=%d\n%s", errno, bpf_log_buf);
    return -1;	
  } 

  if (setsockopt(sd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
    perror("setsockeopt");
    return -1;
  }

  printf("success\n");
  while (1) {
    int i = 0;
    while (i < 3) {
      int key1 = i;
      int value1;
      
      if(bpf_lookup_elem(map_fd, &key1, &value1) < 0) {
	printf("bpf_lookup_elem() err=%d\n%s", errno, bpf_log_buf);
	return -1;	
      }
      printf("key[%d]::value = %d\n", i, value1);
      
      if (i == 0 && value1 == 1) {
	int key2 = 0;
	char value2[4];
	if(bpf_lookup_elem(map_fd2, &key2, value2) < 0) {
	  printf("bpf_lookup_elem() err=%d\n%s", errno, bpf_log_buf);
	  return -1;	
	}
	rev_string(value2);
	printf("recv key:: %s\n", value2);
      }
      
      i++;
    }
    sleep(3);
  }

  close(sd);
  close(map_fd);
  close(map_fd2);
  return 0;
}


int bpf_create_map(enum bpf_map_type map_type, unsigned int key_size, unsigned int value_size, unsigned int max_entries)
{
  union bpf_attr attr;
  memset(&attr, '\0', sizeof(attr));
  
  attr.map_type    = map_type;
  attr.key_size    = key_size;
  attr.value_size  = value_size;
  attr.max_entries = max_entries;
  

  return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns, int prog_len, const char *license)
{
  union bpf_attr attr;
  memset(&attr, '\0', sizeof(attr));
  
  attr.prog_type = type;
  attr.insns     = ptr_to_u64((void *)insns);
  attr.insn_cnt  = prog_len / sizeof(struct bpf_insn);
  attr.license   = ptr_to_u64((void *)license);
  attr.log_buf   = ptr_to_u64(bpf_log_buf);
  attr.log_size  = LOG_BUF_SIZE;
  attr.log_level = 1;
  attr.kern_version = 4;

  bpf_log_buf[0] = 0;
  
  return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_lookup_elem(int fd, const void *key, void *value)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key    = ptr_to_u64(key),
    .value  = ptr_to_u64(value),
  };
  
  return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_update_elem(int fd, const void *key, const void *value, uint64_t flags)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key    = ptr_to_u64(key),
    .value  = ptr_to_u64(value),
    .flags  = flags,
  };
  
  return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_get_next_key(int fd, void *key, void *next_key)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key = ptr_to_u64(key),
    .next_key = ptr_to_u64(next_key),
  };

  return sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

unsigned str_length(const char str[])
{
  unsigned len = 0;
  while (str[len])
    len++;
  return (len);
}

void rev_string(char str[])
{
  int i;
  int len = 4;//str_length(str);
  for (i = 0; i < len / 2; i++) {
    char temp = str[i];
    str[i] = str[len-i-1];
    str[len-i-1] = temp;
  }
  str[5] = 0;
}
