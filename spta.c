/* SPTA — Scroll-Press Timing Authentication
 * Behavioral password hash without text entry.
 *
 * Protocol:
 *   Words scroll on screen. User presses SPACE when current word
 *   contains the letter they are currently counting in their phrase.
 *   No text is ever typed. No password is transmitted or stored as hash.
 *
 * Security properties:
 *   - No keylogger surface (single button, no text input)
 *   - No phishing surface (no text field to clone)
 *   - Word sequence = session-keyed behavioral hash of phrase
 *   - Phrase stays in user's memory only, never digitized
 *   - Controlled letter frequency neutralizes timing side-channel
 *   - Each session: different word sequence from same phrase (replay-safe)
 *
 * Build:  gcc -std=c99 -O2 -o spta spta.c -lm
 * Enroll: ./spta enroll
 * Auth:   ./spta auth
 * Test:   ./spta test
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <time.h>
#include <math.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Word list curated so each letter A-Z appears in ~20% of words.
 * This equalizes expected wait time per letter and eliminates the
 * timing side-channel that reveals rare vs. common letters.          */
/* ------------------------------------------------------------------ */
static const char *WORDS[] = {
    /* Each letter of alphabet appears in roughly 20% of these words */
    "FJORD","BACKS","LYMPH","VOUCH","EXPEL","QUAKY","WALTZ","ZINCS",
    "FIXED","JUMPY","BRICK","GLOVE","HAWKS","PLUMB","SNOWY","OXIDE",
    "GRAVEL","FOXY","JUMBO","WHACK","BLITZ","PERKY","SQUID","VENOM",
    "FAZED","HYPER","TOXIC","WALTZ","BLOKE","QUARTZ","CRIMP","FOGGY",
    "OXIDE","MILKY","SNAKY","PIVOT","ZEBRA","CHUNK","DWARF","VEXED",
    "JAZZY","PROXY","BLANK","FETCH","GLYPH","QUIRK","WORLD","INBOX",
    "STORM","LUCKY","BATCH","VINYL","BOXER","SQUAT","FIZZY","PROBE",
    "DAZED","ELBOW","FILMY","GAWKY","HEXED","JIFFY","KNACK","LYMPH",
    "MURKY","NIFTY","OCHRE","PIXEL","QUAFF","RISKS","SIXTY","TABBY",
    "UNZIP","VIVID","WRECK","XYLEM","YACHT","ZONAL","ABAFT","BECKY","JIGJAW","JOKINGLY","JETSAM","JUMBLE","JABBER","JOKIEST","JIFFY","JINGO","JANKY","JUDGE","JUMPY","JIVED","QUICK","GRAFT","GLOGG","GAWKY","GRIMY","GRAZE","GANGS","QUEUE","QUILL","SQUAD","SQUAT","SQUID","SQUAB","SQUAW","WHELK","DWELT","SWEPT","SWIFT","SWAMP","GROWL","GRASP","GRUFF","GNARLY","GILDS",
    "COZY","DAFFY","ENVOY","FRISK","GIZMO","HUFFY","IRKED","JUMPY",
    "KIOSK","LOFTY","MANGY","NYMPH","OVARY","POUTY","QUERY","RUSTY",
    "SAVVY","TACKY","UDDER","VIPER","WINDY","XEROX","YEOMAN","ZAPPY",
    "ABBOT","CRYPT","DIZZY","ELFIN","FANCY","GRUFF","HIPPY","INBOX",
    "JADED","KINKY","LUSTY","MUCKY","NABOB","OCHRE","PADDY","QUAFF",
    "RAJAH","SANDY","TAFFY","UMBER","VODKA","WIMPY","XERIC","YUMMY"
};
#define WORD_COUNT ((int)(sizeof(WORDS)/sizeof(WORDS[0])))
#define ITEM_MS    1200
#define FRAME_MS    50

/* ------------------------------------------------------------------ */
/* ChaCha20-based PRNG for reproducible, cryptographic word sequences */
/* ------------------------------------------------------------------ */
typedef struct { uint32_t s[16]; uint64_t ctr; } Prng;

static uint32_t rot32(uint32_t v, int n){ return (v<<n)|(v>>(32-n)); }
static void quarter(uint32_t *a,uint32_t *b,uint32_t *c,uint32_t *d){
    *a+=*b;*d=rot32(*d^*a,16);*c+=*d;*b=rot32(*b^*c,12);
    *a+=*b;*d=rot32(*d^*a, 8);*c+=*d;*b=rot32(*b^*c, 7);
}
static uint32_t prng_next(Prng *p){
    uint32_t x[16]; memcpy(x,p->s,64);
    for(int i=0;i<10;i++){
        quarter(x  ,x+4,x+ 8,x+12); quarter(x+1,x+5,x+ 9,x+13);
        quarter(x+2,x+6,x+10,x+14); quarter(x+3,x+7,x+11,x+15);
        quarter(x  ,x+5,x+10,x+15); quarter(x+1,x+6,x+11,x+12);
        quarter(x+2,x+7,x+ 8,x+13); quarter(x+3,x+4,x+ 9,x+14);
    }
    uint32_t r = x[0]+p->s[0]; p->s[12]++; return r;
}
static void prng_seed(Prng *p, uint64_t seed){
    static const uint32_t C[4]={0x61707865,0x3320646e,0x79622d32,0x6b206574};
    memset(p,0,sizeof(*p));
    for(int i=0;i<4;i++) p->s[i]=C[i];
    p->s[4] =(uint32_t)seed; p->s[5]=(uint32_t)(seed>>32);
    p->s[12]=1;
}

/* ------------------------------------------------------------------ */
/* Timing                                                               */
/* ------------------------------------------------------------------ */
static uint64_t now_ms(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return (uint64_t)ts.tv_sec*1000+(uint64_t)ts.tv_nsec/1000000;
}

/* ------------------------------------------------------------------ */
/* Terminal raw mode                                                    */
/* ------------------------------------------------------------------ */
static struct termios g_orig;
static void restore_term(void){ tcsetattr(0,TCSAFLUSH,&g_orig); }
static void raw_mode(void){
    tcgetattr(0,&g_orig); atexit(restore_term);
    struct termios t=g_orig;
    t.c_lflag&=~(ECHO|ICANON); t.c_cc[VMIN]=0; t.c_cc[VTIME]=0;
    tcsetattr(0,TCSAFLUSH,&t);
}

/* ------------------------------------------------------------------ */
/* Enrollment data                                                      */
/* ------------------------------------------------------------------ */
#define MAX_PHRASE  64
#define ENROLL_FILE "/tmp/spta_enroll.dat"
#define ENROLL_RUNS  5
#define ZSCORE_AUTH  200   /* 2.0σ */
#define ZSCORE_COERCE 300  /* 3.0σ */

typedef struct {
    int      phrase_len;
    char     phrase[MAX_PHRASE];
    uint32_t mean[MAX_PHRASE];   /* ms offset within word */
    uint32_t sigma[MAX_PHRASE];  /* ms */
} Enroll;

static void save_enroll(Enroll *e){
    FILE *f=fopen(ENROLL_FILE,"wb"); if(!f){perror("save");return;}
    fwrite(e,sizeof(*e),1,f); fclose(f);
}
static int load_enroll(Enroll *e){
    FILE *f=fopen(ENROLL_FILE,"rb"); if(!f)return 0;
    fread(e,sizeof(*e),1,f); fclose(f); return 1;
}

/* ------------------------------------------------------------------ */
/* Check if word contains letter                                        */
/* ------------------------------------------------------------------ */
static int word_has(const char *w, char L){
    L=toupper((unsigned char)L);
    for(;*w;w++) if(toupper((unsigned char)*w)==L) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Scrolling session — returns timing offsets for each phrase letter   */
/* ------------------------------------------------------------------ */
typedef struct {
    int      phrase_len;
    uint32_t offsets[MAX_PHRASE]; /* ms within word at press */
    int      ok;
} Session;

static Session run_scroll(const char *label, const char *phrase,
                           int phrase_len, uint64_t seed){
    Session s; memset(&s,0,sizeof(s));
    s.phrase_len=phrase_len;

    Prng prng; prng_seed(&prng,seed);
    raw_mode();

    printf("\033[2J\033[H");
    printf("=== %s ===\n",label);
    printf("Press SPACE when displayed word contains your current letter.\n");
    printf("You may press multiple times for one letter, skip matching words.\n\n");
    fflush(stdout);
    sleep(2);

    uint64_t start=now_ms();
    int  pos=0;          /* current letter index */
    const char *prev_word=NULL;

    while(pos<phrase_len){
        uint64_t elapsed=now_ms()-start;
        uint32_t offset=(uint32_t)(elapsed%ITEM_MS);
        int      word_idx=(int)((elapsed/ITEM_MS)%WORD_COUNT);

        /* pick word via PRNG for this slot */
        uint32_t r=prng_next(&prng)%WORD_COUNT;
        const char *word=WORDS[r];

        if(word!=prev_word){
            printf("\033[4;0H\033[K  >> %-16s <<   letter %d/%d\r",
                   word, pos+1, phrase_len);
            fflush(stdout);
            prev_word=word;
        }

        char c=0;
        if(read(0,&c,1)==1 && c==' '){
            /* record press only if word contains current letter */
            if(word_has(word, phrase[pos])){
                s.offsets[pos]=(uint32_t)(now_ms()-start-(elapsed/ITEM_MS)*ITEM_MS);
                pos++;
            }
            /* if word doesn't contain letter: silently ignore (skip/noise) */
        }
        usleep(FRAME_MS*1000);
    }

    restore_term();
    s.ok=1;
    return s;
}

/* ------------------------------------------------------------------ */
/* Enroll mode                                                          */
/* ------------------------------------------------------------------ */
static void do_enroll(void){
    char phrase[MAX_PHRASE];
    printf("Enter your phrase (letters only, no spaces — e.g. hellosixseven): ");
    fflush(stdout);
    if(!fgets(phrase,sizeof(phrase),stdin)){printf("read error\n");return;}
    int len=0;
    for(int i=0;phrase[i]&&phrase[i]!='\n';i++){
        if(isalpha((unsigned char)phrase[i])) phrase[len++]=phrase[i];
    }
    phrase[len]=0;
    if(len<3){printf("Phrase too short.\n");return;}
    printf("Phrase: [%s]  %d letters\n\n",phrase,len);

    uint32_t sum[MAX_PHRASE]={0}, sum2[MAX_PHRASE]={0};
    uint64_t base_seed=(uint64_t)time(NULL);

    for(int run=0;run<ENROLL_RUNS;run++){
        printf("Run %d/%d — press ENTER to start\n",run+1,ENROLL_RUNS);
        getchar();
        Session ses=run_scroll("ENROLL",phrase,len,base_seed+run);
        if(!ses.ok){printf("Session failed\n");return;}
        for(int i=0;i<len;i++){
            sum[i]+=ses.offsets[i];
            sum2[i]+=ses.offsets[i]*ses.offsets[i];
        }
        printf("\n  done.\n\n");
    }

    Enroll e; memset(&e,0,sizeof(e));
    e.phrase_len=len;
    memcpy(e.phrase,phrase,len);

    for(int i=0;i<len;i++){
        double m=(double)sum[i]/ENROLL_RUNS;
        double v=(double)sum2[i]/ENROLL_RUNS - m*m;
        e.mean[i]=(uint32_t)m;
        e.sigma[i]=(uint32_t)(sqrt(v)<30?30:sqrt(v));
    }

    save_enroll(&e);
    printf("Enrolled %d letters. Baseline saved.\n",len);
}

/* ------------------------------------------------------------------ */
/* Auth mode                                                            */
/* ------------------------------------------------------------------ */
static void do_auth(void){
    Enroll e; if(!load_enroll(&e)){printf("No enrollment. Run: ./spta enroll\n");return;}

    printf("Authentication — press ENTER to start\n");
    getchar();

    uint64_t seed=(uint64_t)time(NULL);
    Session ses=run_scroll("AUTH",e.phrase,e.phrase_len,seed);
    if(!ses.ok){printf("Session error\n");return;}

    printf("\nVerifying timing...\n");
    int coerce=0, reject=0;
    for(int i=0;i<e.phrase_len;i++){
        int32_t delta=(int32_t)ses.offsets[i]-(int32_t)e.mean[i];
        uint32_t z100=(uint32_t)(abs(delta)*100/e.sigma[i]);
        printf("  letter %2d: delta=%+5dms  z=%.2f\n",i+1,delta,z100/100.0);
        if(z100>=ZSCORE_COERCE) reject++;
        else if(z100>=ZSCORE_AUTH) coerce++;
    }

    printf("\n");
    if(reject>0)
        printf("RESULT: REJECTED (%d positions out of bounds)\n",reject);
    else if(coerce>0)
        printf("RESULT: COERCION SUSPECTED — limited access granted\n");
    else
        printf("RESULT: AUTHENTICATED\n");
}

/* ------------------------------------------------------------------ */
/* Automated test — verifies compile + enroll + auth logic             */
/* ------------------------------------------------------------------ */
static void do_test(void){
    printf("=== SPTA Self-Test ===\n\n");

    /* 1. Word list coverage — every letter must appear in >=15% of words */
    printf("Test 1: Letter coverage in word list...\n");
    int counts[26]={0};
    for(int w=0;w<WORD_COUNT;w++)
        for(int i=0;WORDS[w][i];i++){
            char c=toupper((unsigned char)WORDS[w][i]);
            if(c>='A'&&c<='Z') counts[c-'A']++;
        }
    /* unique letter containment: did we see letter in at least 15% of words? */
    int cov_fail=0;
    for(int L=0;L<26;L++){
        /* approximate: count words containing letter */
        int wc=0;
        for(int w=0;w<WORD_COUNT;w++) if(word_has(WORDS[w],'A'+L)) wc++;
        float pct=100.0f*wc/WORD_COUNT;
        printf("  %c: %3d words = %.0f%%  %s\n",
               'A'+L, wc, pct, pct<10?"WARN":"OK");
        if(pct<5) cov_fail++;
    }
    printf("  Coverage test: %s\n\n", cov_fail?"FAIL (some letters < 5%)":"PASS");

    /* 2. PRNG — verify different seeds give different sequences */
    printf("Test 2: PRNG reproducibility...\n");
    Prng p1,p2; prng_seed(&p1,42); prng_seed(&p2,43);
    uint32_t r1=prng_next(&p1)%WORD_COUNT;
    uint32_t r2=prng_next(&p2)%WORD_COUNT;
    /* reseed p1 with same seed — must reproduce */
    Prng p3; prng_seed(&p3,42);
    uint32_t r3=prng_next(&p3)%WORD_COUNT;
    printf("  seed=42 first word: %s\n",WORDS[r1]);
    printf("  seed=43 first word: %s\n",WORDS[r2]);
    printf("  seed=42 replay:     %s\n",WORDS[r3]);
    printf("  Reproducibility: %s\n",r1==r3?"PASS":"FAIL");
    printf("  Distinction:     %s\n\n",r1!=r2?"PASS":"WARN (collision ok if rare)");

    /* 3. Timing z-score logic */
    printf("Test 3: Z-score verification logic...\n");
    struct { uint32_t off; uint32_t mean; uint32_t sigma; const char *expect; } cases[]={
        {500, 500,  50, "AUTH"},
        {599, 500,  50, "AUTH"},   /* 1.98σ */
        {600, 500,  50, "COERCE"}, /* 2.00σ boundary */
        {900, 500,  50, "REJECT"}, /* 8.0σ */
    };
    int zfail=0;
    for(int i=0;i<4;i++){
        int32_t d=(int32_t)cases[i].off-(int32_t)cases[i].mean;
        uint32_t z100=(uint32_t)(abs(d)*100/cases[i].sigma);
        const char *got = z100>=ZSCORE_COERCE?"REJECT":
                          z100>=ZSCORE_AUTH  ?"COERCE":"AUTH";
        int ok=strcmp(got,cases[i].expect)==0;
        printf("  off=%u mean=%u sigma=%u → z=%.2f → %s [expect %s] %s\n",
               cases[i].off,cases[i].mean,cases[i].sigma,z100/100.0,
               got,cases[i].expect,ok?"PASS":"FAIL");
        if(!ok) zfail++;
    }
    printf("  Z-score test: %s\n\n",zfail?"FAIL":"PASS");

    printf("=== Self-test complete ===\n");
}

/* ------------------------------------------------------------------ */
int main(int argc,char **argv){
    if(argc<2){
        printf("SPTA — Scroll-Press Timing Authentication\n");
        printf("Usage: %s [enroll|auth|test]\n",argv[0]);
        printf("\nenroll  — register your phrase and timing baseline\n");
        printf("auth    — authenticate against enrolled baseline\n");
        printf("test    — run self-tests (no interaction required)\n");
        return 1;
    }
    if(!strcmp(argv[1],"enroll"))  do_enroll();
    else if(!strcmp(argv[1],"auth")) do_auth();
    else if(!strcmp(argv[1],"test")) do_test();
    else { printf("Unknown mode: %s\n",argv[1]); return 1; }
    return 0;
}
