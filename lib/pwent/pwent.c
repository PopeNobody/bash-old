#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>

static struct passwd passwds[100];
static struct group groups[200];
const size_t BUF_SIZE=1024;

static int pw_pos=-1;
static int gr_pos=-1;

const static void *mmap_bad=(void*)(unsigned long)-1;
struct gai_error {
  int code;
  const char *msg;
};
#define ERROR(x) { x, #x }

#ifndef EAI_ADDRFAMILY
#define EAI_NODATA 1
#endif
#ifndef EAI_ADDRFAMILY
#define EAI_ADDRFAMILY 1
#endif

struct gai_error gai_errors[] = {
  ERROR(EAI_ADDRFAMILY),
  ERROR(EAI_AGAIN),
  ERROR(EAI_BADFLAGS),
  ERROR(EAI_FAIL),
  ERROR(EAI_FAMILY),
  ERROR(EAI_MEMORY),
  ERROR(EAI_NODATA),
  ERROR(EAI_NONAME),
  ERROR(EAI_SERVICE),
  ERROR(EAI_SOCKTYPE),
  ERROR(EAI_SYSTEM),
  {0,0}
};

#define countof(x) sizeof(x)/sizeof(x[0])
static char *next_str(char **pp);


struct group *getgrnam(const char *name) {
  return 0;
};

struct group *getgrgid(gid_t gid) {
  return 0;
};

int getgrnam_r(const char *name, struct group *grp,
    char *buf, size_t buflen, struct group **result)
{
  *result=0;
  return 0;
};

int getgrgid_r(gid_t gid, struct group *grp,
    char *buf, size_t buflen, struct group **result)
{
  *result=0;
  return 0;
};
struct group *getgrent(void) {
  if(gr_pos<0)
    setgrent();    
  if(groups[gr_pos].gr_name==0)
    return 0;
  else
    return groups+gr_pos++;
};
void finish_group(struct group *group){
  char *p=group->gr_name;
  group->gr_passwd=next_str(&p);
  char *str_gid=next_str(&p);
  char *str_mem=next_str(&p);
  group->gr_gid=atoi(str_gid);
  int count=0;
  int i;
  for(i=0;str_mem[i];i++){
    if(str_mem[i]==',')
      count++;
  };
  int length=i;
  group->gr_mem=malloc(sizeof(char*)*count+sizeof(char*));
  count=0;
  for(i=0;i<length;i++){
    group->gr_mem[count++]=str_mem+i;
    while(i<length && str_mem[i]!=',')
      i++;
    if(i<length)
      str_mem[i++]=0;
  };
  group->gr_mem[count++]=0;
};
void setgrent(void){
  static volatile int busy=0;
  while(busy)
    sleep(1);
  busy=1;
  assert(busy);
  if(!groups[0].gr_name){
    memset(groups,0,sizeof(groups));

    int fd=open("/etc/group",O_RDONLY);
    if(fd<0)
      goto done;
    size_t size=lseek(fd,0,SEEK_END);
    const char * const b =mmap(0,size,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0);
    close(fd);
    if(mmap_bad==b)
      goto done;
    const char *e=b+size;
    *(char*)e=0;
    assert(strlen(b)==size);
    const char *p=b;
    struct group group_0;
    struct group group;
    int i=0;
    for(char *p=(char*)b;p<e;){
      const char *l=p;
      group.gr_name=p;
      while(p!=e && *p!='\n')
        ++p;
      if(!*p)
        break;
      *p++=0;
      finish_group(&group);
      if(i==0){
        group_0=group;
      } else {
        groups[i]=group;
      }
      ++i;
    };
    groups[0]=group_0;
    for(int i=0;i<countof(groups);i++){
      if(groups[i].gr_name==0)
        break;
      dprintf(2,"name: %s\n", groups[i].gr_name);
    };
  }
  endgrent();
done:
  busy=0;
};

void endgrent(void){
  gr_pos=0;
};

/* Utility Routines */
static char *next_str(char **pp){
  char *p=*pp;
  while(*p && *p!=':')
    ++p;
  if(*p)
    *p++=0;
  *pp=p;
  return p;
};

/* passwd routines */

struct passwd *getpwuid(uid_t uid) {
  static struct passwd passwd;
  char buf[16*1024];
  static struct passwd *result;
  int res = getpwuid_r(uid, &passwd, buf,sizeof(buf), &result);
  if(res || !result) {
    return 0;
  } else {
    return result;
  };
};
struct passwd *getpwnam(const char *name) {
  static struct passwd passwd;
  char buf[16*1024];
  static struct passwd *result;
  int res = getpwnam_r(name, &passwd, buf,sizeof(buf), &result);
  if(res || !result) {
    return 0;
  } else {
    return result;
  };
};

size_t min(size_t lhs, size_t rhs){
  if(lhs<rhs)
    return lhs;
  else
    return rhs;
};
static int getpw_r(const struct passwd *ent, struct passwd *pwd,
    char *buf, size_t buflen, struct passwd **result)
{
  if(ent){
    memcpy(buf,ent->pw_name,min(BUF_SIZE,buflen));
    pwd->pw_name=    buf;
    pwd->pw_passwd=  buf  +(ent->pw_passwd  -  ent->pw_name);
    pwd->pw_gecos=   buf  +(ent->pw_gecos   -  ent->pw_name);
    pwd->pw_dir=     buf  +(ent->pw_dir     -  ent->pw_name);
    pwd->pw_shell=   buf  +(ent->pw_shell   -  ent->pw_name);
    pwd->pw_gid=ent->pw_gid;
    pwd->pw_uid=ent->pw_uid;
    *result=pwd;
  };
  return 0;
};
int getpwnam_r(const char *name, struct passwd *pwd,
    char *buf, size_t buflen, struct passwd **result)
{
  memset(buf,0,buflen);
  memset(pwd,0,sizeof(*pwd));
  *result=0;

  struct passwd *ent=0;
  while(1){
    ent = getpwent();
    if(!ent)
      break;
    if(!strcmp(name,ent->pw_name))
     break;
  };
  return getpw_r(ent,pwd,buf,buflen,result);
}

int getpwuid_r(uid_t uid, struct passwd *pwd,
    char *buf, size_t buflen, struct passwd **result)
{
  memset(buf,0,buflen);
  memset(pwd,0,sizeof(*pwd));
  *result=0;

  struct passwd *ent=0;
  while(1){
    ent = getpwent();
    if(!ent)
      break;
    if(uid==ent->pw_uid)
     break;
  };
  return getpw_r(ent,pwd,buf,buflen,result);
};
static void finish_passwd(struct passwd *pwd)
{
  assert(pwd);
  char *p=pwd->pw_name;
  pwd->pw_passwd=next_str(&p);
  char *str_uid=next_str(&p);
  pwd->pw_uid=atoi(str_uid);
  char *str_gid=next_str(&p);
  pwd->pw_gid=atoi(str_gid);
  pwd->pw_gecos=next_str(&p);
  pwd->pw_dir=next_str(&p);
  pwd->pw_shell=next_str(&p);
};
void setpwent()
{
  static volatile int busy=0;
  while(busy)
    sleep(1);
  busy=1;
  assert(busy);
  if(!passwds[0].pw_name){
    memset(passwds,0,sizeof(passwds));

    int fd=open("/etc/passwd",O_RDONLY);
    if(fd<0)
      goto done;
    size_t size=lseek(fd,0,SEEK_END);
    const char * const b =mmap(0,size,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0);
    close(fd);
    if(mmap_bad==b)
      goto done;
    const char *e=b+size;
    *(char*)e=0;
    assert(strlen(b)==size);
    const char *p=b;
    struct passwd passwd_0;
    struct passwd passwd;
    int i=0;
    for(char *p=(char*)b;p<e;){
      const char *l=p;
      passwd.pw_name=p;
      while(p!=e && *p!='\n')
        ++p;
      if(!*p)
        break;
      *p++=0;
      finish_passwd(&passwd);
      if(i==0){
        passwd_0=passwd;
      } else {
        passwds[i]=passwd;
      }
      ++i;
    };
    passwds[0]=passwd_0;
    for(int i=0;i<100;i++){
      if(passwds[i].pw_name==0)
        break;
      dprintf(2,"name: %s\n", passwds[i].pw_name);
    };
  }
  endpwent();
done:
  busy=0;
};

void endpwent(void)
{
  pw_pos=0;
};

struct passwd *getpwent(void) {
  if(pw_pos<0)
    setpwent();    
  if(passwds[pw_pos].pw_name==0)
    return 0;
  else
    return passwds+pw_pos++;
};



struct servent *getservent(void)
{
  return 0;
};
void setservent(int stayopen)
{
};

void endservent(void)
{
};

struct servent *getservbyname(const char *name, const char *proto)
{
  return 0;
};

struct servent *getservbyport(int port, const char *proto)
{
  return 0;
};

int getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints,
    struct addrinfo **res)
{
  return EAI_FAIL;
};

void freeaddrinfo(struct addrinfo *res)
{
};

const char *gai_strerror(int errcode)
{
};



