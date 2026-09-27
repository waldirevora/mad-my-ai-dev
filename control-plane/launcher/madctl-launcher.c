#define _GNU_SOURCE
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * MAD's first production trust boundary.  This file deliberately has no
 * library dependency: build_launcher.py links it statically and the resulting
 * executable validates the activation record and both closed trees before it
 * starts Python.  The Python launcher is a second-stage verifier, not a trust
 * anchor.
 */

#ifndef MAD_ACTIVE_RECORD
#define MAD_ACTIVE_RECORD "/etc/mad/active-release.json"
#endif
#ifndef MAD_ACTIVATION_UID
#define MAD_ACTIVATION_UID 0
#endif
#ifndef MAD_SYSTEM_UID
#define MAD_SYSTEM_UID 0
#endif

#define MAX_JSON_TOKENS 262144
#define MAX_FILES 100000

#ifndef DT_AUDIT
#define DT_AUDIT 0x6ffffefc
#endif
#ifndef DT_DEPAUDIT
#define DT_DEPAUDIT 0x6ffffefb
#endif

typedef enum { J_UNDEFINED = 0, J_OBJECT = 1, J_ARRAY = 2, J_STRING = 3, J_PRIMITIVE = 4 } jtype;
typedef struct { jtype type; int start, end, size, parent; } jtok;
typedef struct { unsigned int pos, toknext; int toksuper; } jparser;

typedef struct {
    char *path;
    char mode[5];
    char digest[65];
    int seen;
} file_entry;

typedef struct {
    uint32_t state[8];
    uint64_t bits;
    unsigned char block[64];
    size_t used;
} sha256_ctx;

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void die(const char *message) {
    dprintf(STDERR_FILENO, "madctl-native-launcher: %s\n", message);
    _exit(126);
}
static void die_path(const char *message, const char *path) {
    dprintf(STDERR_FILENO, "madctl-native-launcher: %s: %s\n", message, path);
    _exit(126);
}
static uint32_t rr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static void sha_block(sha256_ctx *c, const unsigned char *p) {
    uint32_t w[64], a,b,d,e,f,g,h,x,t1,t2;
    unsigned i;
    for (i=0;i<16;i++) w[i]=((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];
    for (;i<64;i++) { x=w[i-15]; t1=rr(x,7)^rr(x,18)^(x>>3); x=w[i-2]; t2=rr(x,17)^rr(x,19)^(x>>10); w[i]=w[i-16]+t1+w[i-7]+t2; }
    a=c->state[0]; b=c->state[1]; d=c->state[2]; e=c->state[3]; f=c->state[4]; g=c->state[5]; h=c->state[6]; x=c->state[7];
    for(i=0;i<64;i++) { t1=x+(rr(f,6)^rr(f,11)^rr(f,25))+((f&g)^((~f)&h))+K[i]+w[i]; t2=(rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&d)^(b&d)); x=h;h=g;g=f;f=e+t1;e=d;d=b;b=a;a=t1+t2; }
    c->state[0]+=a;c->state[1]+=b;c->state[2]+=d;c->state[3]+=e;c->state[4]+=f;c->state[5]+=g;c->state[6]+=h;c->state[7]+=x;
}
static void sha_init(sha256_ctx *c) {
    static const uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(c->state,s,sizeof(s)); c->bits=0;c->used=0;
}
static void sha_update(sha256_ctx *c,const unsigned char *p,size_t n) {
    c->bits+=(uint64_t)n*8;
    while(n) { size_t take=64-c->used; if(take>n)take=n; memcpy(c->block+c->used,p,take);c->used+=take;p+=take;n-=take;if(c->used==64){sha_block(c,c->block);c->used=0;} }
}
static void sha_final(sha256_ctx *c,unsigned char out[32]) {
    unsigned i; c->block[c->used++]=0x80;
    if(c->used>56){while(c->used<64)c->block[c->used++]=0;sha_block(c,c->block);c->used=0;}
    while(c->used<56)c->block[c->used++]=0;
    for(i=0;i<8;i++) c->block[63-i]=(unsigned char)(c->bits>>(i*8));
    sha_block(c,c->block);
    for(i=0;i<8;i++){out[i*4]=c->state[i]>>24;out[i*4+1]=c->state[i]>>16;out[i*4+2]=c->state[i]>>8;out[i*4+3]=c->state[i];}
}
static void hex_digest(const unsigned char d[32],char out[65]) { static const char h[]="0123456789abcdef"; unsigned i;for(i=0;i<32;i++){out[i*2]=h[d[i]>>4];out[i*2+1]=h[d[i]&15];}out[64]=0; }
static void digest_bytes(const unsigned char *p,size_t n,char out[65]) { sha256_ctx c;unsigned char d[32];sha_init(&c);sha_update(&c,p,n);sha_final(&c,d);hex_digest(d,out); }

static unsigned char *read_regular(const char *path, uid_t uid, gid_t gid, mode_t exact_mode, size_t *length) {
    struct stat pre, st; int fd; unsigned char *buf; size_t used=0;
    if(lstat(path,&pre)||!S_ISREG(pre.st_mode)||S_ISLNK(pre.st_mode))die_path("required regular file is missing",path);
    fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW); if(fd<0)die_path("cannot open trusted file",path);
    if(fstat(fd,&st)||st.st_dev!=pre.st_dev||st.st_ino!=pre.st_ino||st.st_uid!=uid||(gid!=(gid_t)-1&&st.st_gid!=gid)||
       (exact_mode && (st.st_mode&07777)!=exact_mode)||(st.st_mode&(S_IWGRP|S_IWOTH))){close(fd);die_path("unsafe trusted file identity or mode",path);}
    if(st.st_size<0||(uint64_t)st.st_size>256ULL*1024*1024){close(fd);die_path("trusted file is too large",path);}
    buf=malloc((size_t)st.st_size+1);if(!buf){close(fd);die("out of memory");}
    while(used<(size_t)st.st_size){ssize_t n=read(fd,buf+used,(size_t)st.st_size-used);if(n<=0){close(fd);free(buf);die_path("cannot read trusted file",path);}used+=(size_t)n;}
    buf[used]=0;close(fd);*length=used;return buf;
}
static void digest_file(const char *path,char out[65]) { int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);unsigned char b[65536],d[32];sha256_ctx c;ssize_t n;if(fd<0)die_path("cannot hash trusted file",path);sha_init(&c);while((n=read(fd,b,sizeof(b)))>0)sha_update(&c,b,(size_t)n);if(n<0){close(fd);die_path("cannot hash trusted file",path);}close(fd);sha_final(&c,d);hex_digest(d,out); }

static void jp_init(jparser *p){p->pos=0;p->toknext=0;p->toksuper=-1;}
static jtok *jp_alloc(jparser *p,jtok *t,unsigned count){jtok *x;if(p->toknext>=count)return NULL;x=&t[p->toknext++];x->start=x->end=-1;x->size=0;x->parent=-1;return x;}
static int jp_string(jparser *p,const char *s,size_t n,jtok *t,unsigned count){unsigned start=p->pos;for(p->pos++;p->pos<n;p->pos++){char c=s[p->pos];if(c=='\"'){jtok*x=jp_alloc(p,t,count);if(!x)return -1;x->type=J_STRING;x->start=start+1;x->end=(int)p->pos;x->parent=p->toksuper;return 0;}if((unsigned char)c<32)return -2;if(c=='\\'){p->pos++;if(p->pos>=n||!strchr("\"/\\bfnrtu",s[p->pos]))return -2;if(s[p->pos]=='u'){unsigned i;for(i=0;i<4;i++){p->pos++;if(p->pos>=n||!strchr("0123456789abcdefABCDEF",s[p->pos]))return -2;}}}}return -2;}
static int jp_primitive(jparser*p,const char*s,size_t n,jtok*t,unsigned count){unsigned start=p->pos;for(;p->pos<n;p->pos++){char c=s[p->pos];if(c==','||c==']'||c=='}'||c==':'||c==' '||c=='\t'||c=='\r'||c=='\n')break;if((unsigned char)c<32||c=='\"'||c=='\\')return -2;}if(start==p->pos)return -2;jtok*x=jp_alloc(p,t,count);if(!x)return -1;x->type=J_PRIMITIVE;x->start=(int)start;x->end=(int)p->pos;x->parent=p->toksuper;p->pos--;return 0;}
static int jp_parse(jparser*p,const char*s,size_t n,jtok*t,unsigned count){int r,i;for(;p->pos<n;p->pos++){char c=s[p->pos];jtok*x;switch(c){case'{':case'[':x=jp_alloc(p,t,count);if(!x)return-1;if(p->toksuper!=-1)t[p->toksuper].size++;x->type=c=='{'?J_OBJECT:J_ARRAY;x->start=(int)p->pos;x->parent=p->toksuper;p->toksuper=(int)p->toknext-1;break;case'}':case']':for(i=(int)p->toknext-1;i>=0;i--)if(t[i].start!=-1&&t[i].end==-1){if((c=='}'&&t[i].type!=J_OBJECT)||(c==']'&&t[i].type!=J_ARRAY))return-2;t[i].end=(int)p->pos+1;p->toksuper=t[i].parent;break;}if(i<0)return-2;break;case'\"':r=jp_string(p,s,n,t,count);if(r<0)return r;if(p->toksuper!=-1)t[p->toksuper].size++;break;case'\t':case'\r':case'\n':case' ':case':':case',':break;default:r=jp_primitive(p,s,n,t,count);if(r<0)return r;if(p->toksuper!=-1)t[p->toksuper].size++;break;}}for(i=(int)p->toknext-1;i>=0;i--)if(t[i].start!=-1&&t[i].end==-1)return-2;return(int)p->toknext;}
static int skip_token(const jtok*t,int i){int end=t[i].end;i++;while(t[i].start>=0&&t[i].start<end)i++;return i;}
static int token_eq(const char*j,const jtok*t,const char*s){size_t n=strlen(s);return t->type==J_STRING&&(size_t)(t->end-t->start)==n&&!memcmp(j+t->start,s,n);}
static char *token_string(const char*j,const jtok*t){size_t n;if(t->type!=J_STRING)die("activation field is not a string");n=(size_t)(t->end-t->start);char*x=malloc(n+1);if(!x)die("out of memory");memcpy(x,j+t->start,n);x[n]=0;if(strchr(x,'\\')||strchr(x,'\"'))die("escaped trusted paths are forbidden");return x;}
static long token_int(const char*j,const jtok*t){char b[32],*end;size_t n=(size_t)(t->end-t->start);long v;if(t->type!=J_PRIMITIVE||n>=sizeof(b))die("activation integer is malformed");memcpy(b,j+t->start,n);b[n]=0;errno=0;v=strtol(b,&end,10);if(errno||*end)die("activation integer is malformed");return v;}
static int object_get(const char*j,const jtok*t,int object,const char*key){int i=object+1,found=-1,n=0;if(t[object].type!=J_OBJECT)die("JSON object expected");while(i<MAX_JSON_TOKENS&&t[i].start>=0&&t[i].start<t[object].end-1){int k=i,v=i+1;if(t[k].parent!=object||t[k].type!=J_STRING)die("malformed JSON object");if(token_eq(j,&t[k],key)){if(found!=-1)die("duplicate JSON field");found=v;}i=skip_token(t,v);n++;}if(n*2!=t[object].size)die("malformed JSON object size");return found;}
static int is_sha(const char*s){int i;if(strlen(s)!=64)return 0;for(i=0;i<64;i++)if(!strchr("0123456789abcdef",s[i]))return 0;return 1;}
static int safe_relative(const char*s){const char*p=s;if(!*s||*s=='/')return 0;while(*p){const char*q=strchr(p,'/');size_t n=q?(size_t)(q-p):strlen(p);if(n==0||(n==1&&p[0]=='.')||(n==2&&p[0]=='.'&&p[1]=='.'))return 0;if(!q)break;p=q+1;}return 1;}
static int beneath(const char*path,const char*root){size_t n=strlen(root);return !strncmp(path,root,n)&&(path[n]=='/'||path[n]==0);}
static void join_path(char out[PATH_MAX],const char*a,const char*b){size_t x=strlen(a),y=strlen(b);if(x+1+y>=PATH_MAX)die("trusted path is too long");memcpy(out,a,x);out[x]='/';memcpy(out+x+1,b,y+1);}
static void trusted_ancestors(const char*input,uid_t uid){char path[PATH_MAX],*slash;struct stat st;if(strlen(input)>=sizeof(path))die("trusted path is too long");strcpy(path,input);while(strcmp(path,"/")){slash=strrchr(path,'/');if(!slash)die("trusted path is not absolute");if(slash==path)path[1]=0;else*slash=0;if(lstat(path,&st)||!S_ISDIR(st.st_mode)||S_ISLNK(st.st_mode)||(st.st_uid!=MAD_SYSTEM_UID&&st.st_uid!=uid)||(st.st_mode&(S_IWGRP|S_IWOTH)))die_path("unsafe ancestor of trusted path",path);}}
static void canonical_dir(const char*input,uid_t uid,gid_t gid,char out[PATH_MAX]){char*r;struct stat st;if(input[0]!='/')die_path("trusted directory is not absolute",input);r=realpath(input,out);if(!r||strcmp(input,out)||lstat(out,&st)||!S_ISDIR(st.st_mode)||S_ISLNK(st.st_mode)||st.st_uid!=uid||st.st_gid!=gid||(st.st_mode&07777)!=0555)die_path("trusted directory is not canonical and immutable",input);trusted_ancestors(out,uid);}

static file_entry *find_entry(file_entry *entries,size_t count,const char*relative){size_t i;for(i=0;i<count;i++)if(!strcmp(entries[i].path,relative))return &entries[i];return NULL;}
static void walk_tree(const char*root,const char*relative,file_entry*entries,size_t count,uid_t uid,gid_t gid,const char*inventory,size_t*seen){char dirpath[PATH_MAX];DIR*d;struct dirent*de;struct stat st;if(relative[0])join_path(dirpath,root,relative);else{if(strlen(root)>=PATH_MAX)die("trusted path is too long");strcpy(dirpath,root);}d=opendir(dirpath);if(!d)die_path("cannot open closed directory",dirpath);while((de=readdir(d))){char rel[PATH_MAX],path[PATH_MAX],actual[65],mode[5];file_entry*e;if(!strcmp(de->d_name,".")||!strcmp(de->d_name,".."))continue;if(relative[0])join_path(rel,relative,de->d_name);else{if(strlen(de->d_name)>=PATH_MAX)die("trusted path is too long");strcpy(rel,de->d_name);}join_path(path,root,rel);if(lstat(path,&st)){closedir(d);die_path("cannot stat closed tree entry",path);}if(S_ISLNK(st.st_mode)){closedir(d);die_path("symlink in closed tree",path);}if(st.st_uid!=uid||st.st_gid!=gid){closedir(d);die_path("wrong closed tree owner",path);}if(S_ISDIR(st.st_mode)){if((st.st_mode&07777)!=0555){closedir(d);die_path("writable or wrong-mode closed directory",path);}walk_tree(root,rel,entries,count,uid,gid,inventory,seen);}else if(S_ISREG(st.st_mode)){if(!strcmp(rel,inventory)){if((st.st_mode&07777)!=0444){closedir(d);die_path("wrong inventory mode",path);}continue;}e=find_entry(entries,count,rel);if(!e||e->seen){closedir(d);die_path("unexpected or duplicate closed-tree file",path);}snprintf(mode,sizeof(mode),"%04o",(unsigned)(st.st_mode&07777));if(strcmp(mode,e->mode)){closedir(d);die_path("closed-tree file mode mismatch",path);}digest_file(path,actual);if(strcmp(actual,e->digest)){closedir(d);die_path("closed-tree file digest mismatch",path);}e->seen=1;(*seen)++;}else{closedir(d);die_path("non-regular object in closed tree",path);}}closedir(d);}

static void free_entries(file_entry*entries,size_t count){size_t i;if(!entries)return;for(i=0;i<count;i++)free(entries[i].path);free(entries);}

static void verify_tree(const char*root_input,const char*inventory_name,const char*expected_inventory,const char*expected_tree,uid_t uid,gid_t gid,const char*required1,const char*required2,char root[PATH_MAX],file_entry**ret_entries,size_t*ret_count) {
    char invpath[PATH_MAX],actual[65];size_t n,i,count=0,seen=0;unsigned char*raw; jtok*tokens; jparser parser;int parsed,files,index;file_entry*entries;
    canonical_dir(root_input,uid,gid,root);join_path(invpath,root,inventory_name);raw=read_regular(invpath,uid,gid,0444,&n);digest_bytes(raw,n,actual);if(strcmp(actual,expected_inventory))die("closed inventory digest mismatch");
    tokens=calloc(MAX_JSON_TOKENS,sizeof(*tokens));if(!tokens)die("out of memory");for(i=0;i<MAX_JSON_TOKENS;i++)tokens[i].start=-1;jp_init(&parser);parsed=jp_parse(&parser,(char*)raw,n,tokens,MAX_JSON_TOKENS);if(parsed<1||tokens[0].type!=J_OBJECT||tokens[0].end!=(int)n-1||raw[n-1]!='\n')die("closed inventory JSON is not canonical framing");
    index=object_get((char*)raw,tokens,0,"schema_version");if(index<0||token_int((char*)raw,&tokens[index])!=1)die("closed inventory schema mismatch");files=object_get((char*)raw,tokens,0,"files");if(files<0||tokens[files].type!=J_OBJECT)die("closed inventory files object missing");digest_bytes(raw+tokens[files].start,(size_t)(tokens[files].end-tokens[files].start),actual);if(strcmp(actual,expected_tree))die("closed tree digest mismatch");
    count=(size_t)tokens[files].size/2;if(!count||count>MAX_FILES)die("closed inventory file count is invalid");entries=calloc(count,sizeof(*entries));if(!entries)die("out of memory");index=files+1;i=0;while(index<parsed&&tokens[index].start<tokens[files].end-1){int key=index,record=index+1,m,s;if(i>=count||tokens[key].type!=J_STRING||tokens[record].type!=J_OBJECT)die("malformed inventory entry");entries[i].path=token_string((char*)raw,&tokens[key]);if(!safe_relative(entries[i].path))die("unsafe inventory path");m=object_get((char*)raw,tokens,record,"mode");s=object_get((char*)raw,tokens,record,"sha256");if(m<0||s<0)die("incomplete inventory entry");char*ms=token_string((char*)raw,&tokens[m]);char*hs=token_string((char*)raw,&tokens[s]);if(strlen(ms)!=4||!is_sha(hs)||tokens[record].size!=4)die("malformed inventory record");memcpy(entries[i].mode,ms,5);memcpy(entries[i].digest,hs,65);free(ms);free(hs);i++;index=skip_token(tokens,record);}if(i!=count)die("inventory count mismatch");
    if(required1&&!find_entry(entries,count,required1)) die_path("closed inventory lacks required file",required1);
    if(required2&&!find_entry(entries,count,required2)) die_path("closed inventory lacks required file",required2);
    walk_tree(root,"",entries,count,uid,gid,inventory_name,&seen);if(seen!=count)die("closed inventory contains missing files");
    free(tokens);free(raw);if(ret_entries){*ret_entries=entries;*ret_count=count;}else free_entries(entries,count);
}

static int inventory_has(file_entry*entries,size_t count,const char*relative){return find_entry(entries,count,relative)!=NULL;}
static size_t checked_range(uint64_t offset,uint64_t length,size_t total,const char*what){if(offset>total||length>total-offset)die_path("malformed ELF range",what);return(size_t)offset;}
static size_t vaddr_offset(const Elf64_Phdr*ph,size_t count,Elf64_Addr address,size_t total,const char*relative){size_t i;for(i=0;i<count;i++)if(ph[i].p_type==PT_LOAD&&address>=ph[i].p_vaddr&&address-ph[i].p_vaddr<ph[i].p_filesz){uint64_t off=ph[i].p_offset+(address-ph[i].p_vaddr);checked_range(off,1,total,relative);return(size_t)off;}die_path("ELF dynamic string table is not file-backed",relative);return 0;}
static const char*elf_string(const unsigned char*raw,size_t total,size_t table,size_t table_size,Elf64_Xword index,const char*relative){const char*s;if(index>=table_size||table>total||table_size>total-table)die_path("ELF dynamic string index is invalid",relative);s=(const char*)raw+table+(size_t)index;if(!memchr(s,0,table_size-(size_t)index))die_path("ELF dynamic string is unterminated",relative);return s;}

static void verify_search_path(const char*root,const char*elf_path,const char*value,const char*relative){
    char origin[PATH_MAX],component[PATH_MAX],expanded[PATH_MAX],resolved[PATH_MAX];const char*cursor=value;char*slash;size_t root_len=strlen(root);
    if(strlen(elf_path)>=sizeof(origin))die_path("ELF path is too long",relative);
    strcpy(origin,elf_path);slash=strrchr(origin,'/');if(!slash)die_path("ELF origin is malformed",relative);*slash=0;
    while(1){const char*end=strchr(cursor,':');size_t length=end?(size_t)(end-cursor):strlen(cursor),used=0,i;if(!length||length>=sizeof(component))die_path("unsupported empty or oversized ELF search path",relative);memcpy(component,cursor,length);component[length]=0;
        for(i=0;i<length;){const char*replacement=NULL;size_t token=0,replacement_length;if(component[i]=='$'){if(!strncmp(component+i,"$ORIGIN",7)){replacement=origin;token=7;}else if(!strncmp(component+i,"${ORIGIN}",9)){replacement=origin;token=9;}else die_path("unsupported ELF search-path substitution",relative);}if(replacement){replacement_length=strlen(replacement);if(used+replacement_length>=sizeof(expanded))die_path("ELF search path is too long",relative);memcpy(expanded+used,replacement,replacement_length);used+=replacement_length;i+=token;}else{if(used+1>=sizeof(expanded))die_path("ELF search path is too long",relative);expanded[used++]=component[i++];}}
        expanded[used]=0;if(expanded[0]!='/'||!realpath(expanded,resolved)||strncmp(resolved,root,root_len)||resolved[root_len]!='/')die_path("ELF search path escapes trusted runtime",relative);if(!end)break;cursor=end+1;
    }
}

static void reject_system_loader_preload(void){struct stat st;if(lstat("/etc/ld.so.preload",&st)==0)die("system loader preload configuration is unsupported");if(errno!=ENOENT)die("cannot establish absence of system loader preload configuration");}

static void verify_elf_file(const char*root,const char*relative,file_entry*entries,size_t count,uid_t uid,gid_t gid,int python_entry){
    char path[PATH_MAX],expected[PATH_MAX],interpreter_rel[PATH_MAX];size_t length,phoff,i,dyn_count=0,strtab=0,strsz=0;unsigned char*raw;Elf64_Ehdr*eh;Elf64_Phdr*ph;Elf64_Dyn*dyn=NULL;int interp_count=0,has_dynamic=0,direct_library=!strncmp(relative,"lib/",4)&&!strchr(relative+4,'/');
    join_path(path,root,relative);raw=read_regular(path,uid,gid,0,&length);if(length<SELFMAG||memcmp(raw,ELFMAG,SELFMAG)){free(raw);if(python_entry||direct_library)die_path("required executable dependency is not ELF",relative);return;}
    if(length<sizeof(Elf64_Ehdr))die_path("truncated ELF header",relative);
    eh=(Elf64_Ehdr*)raw;
    if(eh->e_type==ET_REL&&!python_entry&&!direct_library){free(raw);return;}
#if defined(__x86_64__)
    if(eh->e_machine!=EM_X86_64)die_path("ELF architecture is unsupported",relative);
#elif defined(__aarch64__)
    if(eh->e_machine!=EM_AARCH64)die_path("ELF architecture is unsupported",relative);
#else
#error unsupported native launcher architecture
#endif
    if(eh->e_ident[EI_CLASS]!=ELFCLASS64||eh->e_ident[EI_DATA]!=ELFDATA2LSB||eh->e_ident[EI_VERSION]!=EV_CURRENT||eh->e_version!=EV_CURRENT||(eh->e_type!=ET_EXEC&&eh->e_type!=ET_DYN)||eh->e_phentsize!=sizeof(Elf64_Phdr)||!eh->e_phnum)die_path("unsupported ELF contract",relative);
    phoff=checked_range(eh->e_phoff,(uint64_t)eh->e_phnum*sizeof(Elf64_Phdr),length,relative);ph=(Elf64_Phdr*)(raw+phoff);
    for(i=0;i<eh->e_phnum;i++){
        if(ph[i].p_type==PT_INTERP){const char*value;size_t off=checked_range(ph[i].p_offset,ph[i].p_filesz,length,relative);if(++interp_count!=1||!ph[i].p_filesz)die_path("ELF interpreter contract is malformed",relative);value=(const char*)raw+off;if(!memchr(value,0,(size_t)ph[i].p_filesz)||value[0]!='/')die_path("ELF interpreter is not an absolute terminated path",relative);if(strlen(value)>=sizeof(expected)||realpath(value,expected)==NULL||strncmp(expected,root,strlen(root))||expected[strlen(root)]!='/')die_path("ELF interpreter escapes trusted runtime",relative);snprintf(interpreter_rel,sizeof(interpreter_rel),"%s",expected+strlen(root)+1);if(!safe_relative(interpreter_rel)||!inventory_has(entries,count,interpreter_rel))die_path("ELF interpreter is absent from trusted runtime inventory",relative);}
        if(ph[i].p_type==PT_DYNAMIC){size_t off=checked_range(ph[i].p_offset,ph[i].p_filesz,length,relative);if(ph[i].p_filesz%sizeof(Elf64_Dyn)||has_dynamic)die_path("ELF dynamic table contract is malformed",relative);dyn=(Elf64_Dyn*)(raw+off);dyn_count=(size_t)ph[i].p_filesz/sizeof(Elf64_Dyn);has_dynamic=1;}
    }
    if(python_entry&&has_dynamic&&!interp_count)die_path("dynamic Python executable lacks an in-runtime interpreter",relative);
    if(has_dynamic){Elf64_Addr straddr=0;for(i=0;i<dyn_count&&dyn[i].d_tag!=DT_NULL;i++){if(dyn[i].d_tag==DT_STRTAB)straddr=dyn[i].d_un.d_ptr;else if(dyn[i].d_tag==DT_STRSZ)strsz=(size_t)dyn[i].d_un.d_val;else if(dyn[i].d_tag==DT_AUDIT||dyn[i].d_tag==DT_DEPAUDIT||dyn[i].d_tag==DT_FILTER||dyn[i].d_tag==DT_AUXILIARY)die_path("unsupported ELF loader directive",relative);}if(i==dyn_count)die_path("unterminated ELF dynamic table",relative);if(!straddr||!strsz)die_path("ELF dynamic string table is missing",relative);strtab=vaddr_offset(ph,eh->e_phnum,straddr,length,relative);checked_range(strtab,strsz,length,relative);for(i=0;i<dyn_count&&dyn[i].d_tag!=DT_NULL;i++){if(dyn[i].d_tag==DT_NEEDED){const char*needed=elf_string(raw,length,strtab,strsz,dyn[i].d_un.d_val,relative);if(!*needed||strchr(needed,'/'))die_path("unsafe ELF dependency name",relative);if(snprintf(expected,sizeof(expected),"lib/%s",needed)>=(int)sizeof(expected)||!inventory_has(entries,count,expected))die_path("ELF dependency is absent from trusted runtime inventory",relative);}else if(dyn[i].d_tag==DT_RPATH||dyn[i].d_tag==DT_RUNPATH)verify_search_path(root,path,elf_string(raw,length,strtab,strsz,dyn[i].d_un.d_val,relative),relative);}}
    free(raw);
}

static void verify_elf_closure(const char*root,const char*python_relative,file_entry*entries,size_t count,uid_t uid,gid_t gid){size_t i;int found=0;for(i=0;i<count;i++){int is_python=!strcmp(entries[i].path,python_relative);verify_elf_file(root,entries[i].path,entries,count,uid,gid,is_python);if(is_python)found=1;}if(!found)die("activated Python executable is absent from runtime inventory");}

static char *field_string(const char*j,const jtok*t,const char*name){int x=object_get(j,t,0,name);if(x<0)die_path("activation field missing",name);return token_string(j,&t[x]);}
static long field_int(const char*j,const jtok*t,const char*name){int x=object_get(j,t,0,name);if(x<0)die_path("activation field missing",name);return token_int(j,&t[x]);}
static void check_top_fields(const char*j,const jtok*t){
    static const char*allowed[]={"schema_version","trusted_uid","trusted_gid","trusted_system_uid","expected_mad_version","release_root","release_digest","inventory_digest","native_launcher_path","native_launcher_sha256","python_runtime_root","python_executable","python_runtime_digest","python_runtime_inventory_digest","state_root","registry_root","human_approval_registry_root","cache_root","controller_key_path","codex_home","tools","orka"};
    int i=1,k,a,count=0;while(t[i].start>=0&&t[i].start<t[0].end-1){for(a=0;a<(int)(sizeof(allowed)/sizeof(allowed[0]));a++)if(token_eq(j,&t[i],allowed[a]))break;if(a==(int)(sizeof(allowed)/sizeof(allowed[0])))die("activation record has unknown fields");k=i+1;i=skip_token(t,k);count++;}if(count!=(int)(sizeof(allowed)/sizeof(allowed[0]))||t[0].size!=count*2)die("activation record has missing or duplicate fields");
}

int main(int argc,char**argv){
    size_t n,i,runtime_count=0;unsigned char*raw;struct stat st;jtok*tokens;jparser parser;int parsed;uid_t uid;gid_t gid;char self[PATH_MAX],release[PATH_MAX],runtime[PATH_MAX],internal[PATH_MAX],exe_rel[PATH_MAX],runtime_lib[PATH_MAX],loader_env[PATH_MAX+32],python_home_env[PATH_MAX+32];ssize_t slen;char actual[65];file_entry*runtime_entries=NULL;
    char *version,*release_in,*release_digest,*inventory_digest,*launcher_path,*launcher_digest,*runtime_in,*python,*runtime_digest,*runtime_inventory;
    raw=read_regular(MAD_ACTIVE_RECORD,MAD_ACTIVATION_UID,(gid_t)-1,0,&n); /* gid checked after parsing */
    tokens=calloc(MAX_JSON_TOKENS,sizeof(*tokens));if(!tokens)die("out of memory");for(i=0;i<MAX_JSON_TOKENS;i++)tokens[i].start=-1;jp_init(&parser);parsed=jp_parse(&parser,(char*)raw,n,tokens,MAX_JSON_TOKENS);if(parsed<1||tokens[0].type!=J_OBJECT||tokens[0].end!=(int)n-1||raw[n-1]!='\n')die("activation record JSON has invalid framing");check_top_fields((char*)raw,tokens);
    if(field_int((char*)raw,tokens,"schema_version")!=1) die("unsupported activation schema");
    uid=(uid_t)field_int((char*)raw,tokens,"trusted_uid");
    gid=(gid_t)field_int((char*)raw,tokens,"trusted_gid");
    if(uid!=MAD_ACTIVATION_UID||field_int((char*)raw,tokens,"trusted_system_uid")!=MAD_SYSTEM_UID)
        die("activation trusted identity does not match the installed launcher");
    version=field_string((char*)raw,tokens,"expected_mad_version");
    if(strcmp(version,"2.0.0")) die("activated MAD version is unsupported");
    free(version);
    if(lstat(MAD_ACTIVE_RECORD,&st)||st.st_uid!=uid||st.st_gid!=gid||(st.st_mode&(S_IWGRP|S_IWOTH)))
        die("activation record ownership or permissions are unsafe");
    trusted_ancestors(MAD_ACTIVE_RECORD,uid);
    launcher_path=field_string((char*)raw,tokens,"native_launcher_path");launcher_digest=field_string((char*)raw,tokens,"native_launcher_sha256");if(!is_sha(launcher_digest))die("native launcher digest is malformed");slen=readlink("/proc/self/exe",self,sizeof(self)-1);if(slen<1||(size_t)slen>=sizeof(self)-1)die("cannot identify running native launcher");self[slen]=0;char resolved[PATH_MAX];if(!realpath(self,resolved)||strcmp(resolved,launcher_path)||lstat(resolved,&st)||!S_ISREG(st.st_mode)||S_ISLNK(st.st_mode)||st.st_uid!=uid||st.st_gid!=gid||(st.st_mode&(S_IWGRP|S_IWOTH))||!(st.st_mode&S_IXUSR))die("running native launcher identity is not activated");trusted_ancestors(resolved,uid);digest_file(resolved,actual);if(strcmp(actual,launcher_digest))die("native launcher digest mismatch");
    release_in=field_string((char*)raw,tokens,"release_root");release_digest=field_string((char*)raw,tokens,"release_digest");inventory_digest=field_string((char*)raw,tokens,"inventory_digest");if(!is_sha(release_digest)||!is_sha(inventory_digest))die("release digest is malformed");verify_tree(release_in,"release-files.json",inventory_digest,release_digest,uid,gid,"launcher/madctl-launcher.py","python/madctl/activation.py",release,NULL,NULL);
    runtime_in=field_string((char*)raw,tokens,"python_runtime_root");python=field_string((char*)raw,tokens,"python_executable");runtime_digest=field_string((char*)raw,tokens,"python_runtime_digest");runtime_inventory=field_string((char*)raw,tokens,"python_runtime_inventory_digest");if(!is_sha(runtime_digest)||!is_sha(runtime_inventory))die("Python runtime digest is malformed");canonical_dir(runtime_in,uid,gid,runtime);if(!beneath(python,runtime)||python[strlen(runtime)]!='/')die("Python executable escapes trusted runtime");snprintf(exe_rel,sizeof(exe_rel),"%s",python+strlen(runtime)+1);verify_tree(runtime_in,"python-runtime-files.json",runtime_inventory,runtime_digest,uid,gid,exe_rel,"python-runtime.json",runtime,&runtime_entries,&runtime_count);verify_elf_closure(runtime,exe_rel,runtime_entries,runtime_count,uid,gid);free_entries(runtime_entries,runtime_count);
    if(lstat(python,&st)||!S_ISREG(st.st_mode)||S_ISLNK(st.st_mode)||st.st_uid!=uid||st.st_gid!=gid||!(st.st_mode&S_IXUSR)||(st.st_mode&(S_IWGRP|S_IWOTH)))
        die("trusted Python executable identity is unsafe");
    join_path(internal,release,"launcher/madctl-launcher.py");
    char **child=calloc((size_t)argc+9,sizeof(char*));if(!child)die("out of memory");child[0]=python;child[1]="-P";child[2]="-s";child[3]="-S";child[4]="-B";child[5]=internal;child[6]="--mad-active-record";child[7]=MAD_ACTIVE_RECORD;for(i=1;i<(size_t)argc;i++)child[i+7]=argv[i];child[argc+7]=NULL;
    join_path(runtime_lib,runtime,"lib");if(lstat(runtime_lib,&st)||!S_ISDIR(st.st_mode)||S_ISLNK(st.st_mode)||st.st_uid!=uid||st.st_gid!=gid||(st.st_mode&07777)!=0555)die("trusted Python library directory is unsafe");if(snprintf(loader_env,sizeof(loader_env),"LD_LIBRARY_PATH=%s",runtime_lib)>=(int)sizeof(loader_env))die("trusted loader path is too long");if(snprintf(python_home_env,sizeof(python_home_env),"PYTHONHOME=%s",runtime)>=(int)sizeof(python_home_env))die("trusted Python home is too long");reject_system_loader_preload();
    char *env[]={"LANG=C","LC_ALL=C","PATH=/nonexistent","HOME=/nonexistent","PYTHONHASHSEED=0","PYTHONDONTWRITEBYTECODE=1",loader_env,python_home_env,NULL};
    pid_t child_pid=fork();if(child_pid<0)die("cannot fork trusted Python runtime");if(child_pid==0){reject_system_loader_preload();execve(python,child,env);die_path("cannot execute trusted Python runtime",python);}int status;while(waitpid(child_pid,&status,0)<0){if(errno!=EINTR)die("cannot wait for trusted Python runtime");}if(WIFEXITED(status))return WEXITSTATUS(status);if(WIFSIGNALED(status))return 128+WTERMSIG(status);return 126;
}
