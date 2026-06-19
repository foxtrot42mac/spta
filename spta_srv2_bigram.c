/* spta_srv2_bigram.c — SPTA Bigram Authentication Server
 *
 * Build: gcc -std=c99 -O2 -o spta_srv2_bigram spta_srv2_bigram.c -lm
 * Run:   ./spta_srv2_bigram [port]   (default 8009)
 *
 * Protocol (newline-terminated text):
 *   S->C: SESSION <seed_hex>\n
 *   S->C: WORDS <w0> <w1> ... <w511>\n
 *   S->C: READY\n
 *   C->S: PRESS <word_idx> <ms>\n    (one per bigram)
 *   C->S: DONE\n
 *   S->C: RESULT AUTH|COERCE|REJECT\n
 *   S->C: DETAIL <info>\n
 *
 * Bigram auth: phrase "helloworld" -> bigrams "he","ll","ow","or","ld"
 * A word qualifies for bigram "XY" iff it contains BOTH letter X AND letter Y.
 * Monogram (last char of odd-length phrase): word just needs to contain X.
 * Z-score timing check same as original SPTA (2sigma=coerce, 3sigma=reject).
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>

/* ================================================================== */
/* Word list — each letter appears in ~20% of words                    */
/* Extra words added to ensure bigram coverage for "helloworld"        */
/* ================================================================== */
static const char *WORDS[] = {
    /* original spta.c list */
    "FJORD","BACKS","LYMPH","VOUCH","EXPEL","QUAKY","WALTZ","ZINCS",
    "FIXED","JUMPY","BRICK","GLOVE","HAWKS","PLUMB","SNOWY","OXIDE",
    "GRAVEL","FOXY","JUMBO","WHACK","BLITZ","PERKY","SQUID","VENOM",
    "FAZED","HYPER","TOXIC","BLOKE","QUARTZ","CRIMP","FOGGY",
    "MILKY","SNAKY","PIVOT","ZEBRA","CHUNK","DWARF","VEXED",
    "JAZZY","PROXY","BLANK","FETCH","GLYPH","QUIRK","WORLD","INBOX",
    "STORM","LUCKY","BATCH","VINYL","BOXER","SQUAT","FIZZY","PROBE",
    "DAZED","ELBOW","FILMY","GAWKY","HEXED","JIFFY","KNACK","LYMPH",
    "MURKY","NIFTY","OCHRE","PIXEL","QUAFF","RISKS","SIXTY","TABBY",
    "UNZIP","VIVID","WRECK","XYLEM","YACHT","ZONAL","ABAFT","BECKY",
    "JETSAM","JUMBLE","JABBER","JINGO","JANKY","JUDGE","JIVED","QUICK",
    "GRAFT","GAWKY","GRIMY","GRAZE","GANGS","QUEUE","QUILL","SQUAD",
    "SQUAB","SQUAW","WHELK","DWELT","SWEPT","SWIFT","SWAMP",
    "GROWL","GRASP","GRUFF","GILDS",
    "COZY","DAFFY","ENVOY","FRISK","GIZMO","HUFFY","IRKED",
    "KIOSK","LOFTY","MANGY","NYMPH","OVARY","POUTY","QUERY","RUSTY",
    "SAVVY","TACKY","UDDER","VIPER","WINDY","XEROX","YEOMAN","ZAPPY",
    "ABBOT","CRYPT","DIZZY","ELFIN","FANCY","HIPPY",
    "JADED","KINKY","LUSTY","MUCKY","NABOB","PADDY",
    "RAJAH","SANDY","TAFFY","UMBER","VODKA","WIMPY","XERIC","YUMMY",
    /* bigram "he": words with H and E */
    "FETCH","HEXED","SHELF","WHEEL","WHERE","THEME","THESE","THERE",
    "HENCE","SHRED","HOVER","THEM","ETHER","HEMP","SHEEN","HEWED",
    /* bigram "ll": words with L (double-l need just one L check) */
    "WALTZ","GLYPH","GLOVE","FILMY","WORLD","PIXEL","PLUMB","LYMPH",
    "PILLAR","SKULL","SPILL","TROLL","BELLE","YELL","BELL","FILL",
    "HILL","KILL","MILL","BILL","DILL","GILL","PILL","TILL","WILL",
    /* bigram "ow": words with O and W */
    "WORLD","SNOWY","ELBOW","GROWL","BLOWN","FLOWS","BELOW","WIDOW",
    "OWING","OWNED","BOWER","LOWER","MOWER","POWER","TOWER","VOWEL",
    "SHOWN","BROWN","CLOWN","DROWN","FROWN","GROWN","KNOWN","PLOW",
    /* bigram "or": words with O and R */
    "FJORD","STORM","WORLD","PROXY","BOXER","PROBE","OCHRE","GRAVEL",
    "MANOR","MINOR","DONOR","HONOR","MOTOR","TUTOR","RAZOR","HUMOR",
    "FLOOR","GROOR","VAPOR","VALOR","LABOR","FAVOR","COLOR","DOLOR",
    /* bigram "ld": words with L and D */
    "WORLD","GUILD","YIELD","FIELD","SHIELD","WIELD","BUILD","CHILD",
    "MOULD","COULD","WOULD","SHOULD","ADULT","BLAND","BLEND","BLIND",
    "BLOOD","BLOND","CLOUD","CLUED","FLOOD","FLUID","GELID","VALID",
    /* extra coverage */
    "HOLY","HOLD","COLD","BOLD","FOLD","GOLD","MOLD","SOLD","TOLD","OLD",
    "WHOLE","WHILE","WHALE","WHEEL","SHELL","SMELL","SPELL","SWELL","DWELL",
    "HELLO","BELOW","ELBOW","ALLOW","ELLOW","ENDOW","ELBOW","WIDOW",
};
#define WORD_COUNT  ((int)(sizeof(WORDS)/sizeof(WORDS[0])))
#define SESSION_WORDS 512

/* ================================================================== */
/* ChaCha20 PRNG                                                        */
/* ================================================================== */
typedef struct { uint32_t s[16]; } Prng;

static uint32_t rot32(uint32_t v, int n){ return (v<<n)|(v>>(32-n)); }

static void qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d){
    *a+=*b; *d=rot32(*d^*a,16); *c+=*d; *b=rot32(*b^*c,12);
    *a+=*b; *d=rot32(*d^*a, 8); *c+=*d; *b=rot32(*b^*c, 7);
}

static uint32_t prng_next(Prng *p){
    uint32_t x[16]; memcpy(x, p->s, 64);
    for(int i=0;i<10;i++){
        qr(x,x+4,x+8,x+12);   qr(x+1,x+5,x+9,x+13);
        qr(x+2,x+6,x+10,x+14); qr(x+3,x+7,x+11,x+15);
        qr(x,x+5,x+10,x+15);  qr(x+1,x+6,x+11,x+12);
        qr(x+2,x+7,x+8,x+13); qr(x+3,x+4,x+9,x+14);
    }
    uint32_t r = x[0]+p->s[0]; p->s[12]++; return r;
}

static void prng_seed(Prng *p, uint64_t seed){
    static const uint32_t C[4]={0x61707865,0x3320646e,0x79622d32,0x6b206574};
    memset(p->s, 0, 64);
    p->s[0]=C[0]; p->s[1]=C[1]; p->s[2]=C[2]; p->s[3]=C[3];
    p->s[4]=(uint32_t)seed; p->s[5]=(uint32_t)(seed>>32);
    p->s[12]=1;
}

/* ================================================================== */
/* Bigram enrollment                                                    */
/* ================================================================== */
#define MAX_BIGRAMS  32
#define ZSCORE_AUTH   200   /* 2.0sigma x100 */
#define ZSCORE_COERCE 300   /* 3.0sigma x100 */

typedef struct {
    int      n;
    char     bg[MAX_BIGRAMS][3];   /* "xy" or "x\0" for monogram */
    uint32_t mean[MAX_BIGRAMS];    /* ms */
    uint32_t sigma[MAX_BIGRAMS];   /* ms */
} BigramEnroll;

static void phrase_to_bigrams(const char *phrase, int plen, BigramEnroll *e){
    e->n = 0;
    for(int i = 0; i < plen && e->n < MAX_BIGRAMS; i += 2){
        e->bg[e->n][0] = (char)tolower((unsigned char)phrase[i]);
        e->bg[e->n][1] = (i+1 < plen) ? (char)tolower((unsigned char)phrase[i+1]) : '\0';
        e->bg[e->n][2] = '\0';
        e->n++;
    }
}

/* Returns 1 if word contains both characters of bigram bg.
 * For monogram (bg[1]==0) only checks first character. */
static int word_has_bigram(const char *word, const char *bg){
    char a = (char)toupper((unsigned char)bg[0]);
    char b = bg[1] ? (char)toupper((unsigned char)bg[1]) : '\0';
    int has_a = 0, has_b = (b == '\0') ? 1 : 0;
    for(const char *p = word; *p; p++){
        char c = (char)toupper((unsigned char)*p);
        if(c == a) has_a = 1;
        if(b && c == b) has_b = 1;
    }
    return has_a && has_b;
}

/* ================================================================== */
/* Global enrollment — hardcoded for test phrase "helloworld"          */
/* bigrams: he, ll, ow, or, ld  |  mean=600ms  sigma=100ms            */
/* ================================================================== */
static BigramEnroll g_enroll;

static void init_enroll(void){
    const char *phrase = "helloworld";
    phrase_to_bigrams(phrase, (int)strlen(phrase), &g_enroll);
    for(int i = 0; i < g_enroll.n; i++){
        g_enroll.mean[i]  = 600;
        g_enroll.sigma[i] = 100;
    }
    printf("[enroll] phrase='%s'  bigrams=%d:", phrase, g_enroll.n);
    for(int i = 0; i < g_enroll.n; i++)
        printf(" '%s'", g_enroll.bg[i]);
    printf("\n[enroll] mean=600ms  sigma=100ms per bigram\n\n");
}

/* ================================================================== */
/* IO helpers                                                           */
/* ================================================================== */
static int send_all(int fd, const char *buf, size_t len){
    size_t sent = 0;
    while(sent < len){
        ssize_t r = write(fd, buf+sent, len-sent);
        if(r <= 0) return -1;
        sent += (size_t)r;
    }
    return 0;
}

static int send_line(int fd, const char *msg){
    return send_all(fd, msg, strlen(msg));
}

/* Read until '\n' or EOF. Returns chars read (without '\n'), -1 on error. */
static int read_line(int fd, char *buf, int maxlen){
    int n = 0;
    while(n < maxlen-1){
        char c;
        ssize_t r = read(fd, &c, 1);
        if(r <= 0) return -1;
        if(c == '\n'){ buf[n] = '\0'; return n; }
        if(c != '\r') buf[n++] = c;
    }
    buf[n] = '\0';
    return n;
}

/* ================================================================== */
/* Handle one client connection                                         */
/* ================================================================== */
static void handle_client(int fd, struct sockaddr_in *addr){
    char peer[64];
    snprintf(peer, sizeof(peer), "%s:%d",
             inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    printf("[client] %s connected\n", peer);

    /* Session seed */
    uint64_t seed = ((uint64_t)time(NULL) * 6364136223846793005ULL)
                    ^ ((uint64_t)(uintptr_t)addr ^ ((uint64_t)getpid()<<17));
    Prng prng; prng_seed(&prng, seed);

    /* Build word index table for this session */
    int widx[SESSION_WORDS];
    for(int i = 0; i < SESSION_WORDS; i++)
        widx[i] = (int)(prng_next(&prng) % (uint32_t)WORD_COUNT);

    /* --- SESSION --- */
    char line[128];
    snprintf(line, sizeof(line), "SESSION %016llx\n", (unsigned long long)seed);
    if(send_line(fd, line) < 0) goto done;

    /* --- WORDS --- */
    /* Max: "WORDS" + 512*(8+1) + "\n" ~ 5000 bytes */
    char *wbuf = malloc(SESSION_WORDS * 12 + 16);
    if(!wbuf){ send_line(fd, "ERROR out_of_memory\n"); goto done; }
    int off = 0;
    off += sprintf(wbuf+off, "WORDS");
    for(int i = 0; i < SESSION_WORDS; i++)
        off += sprintf(wbuf+off, " %s", WORDS[widx[i]]);
    off += sprintf(wbuf+off, "\n");
    if(send_all(fd, wbuf, (size_t)off) < 0){ free(wbuf); goto done; }
    free(wbuf);

    /* --- READY --- */
    if(send_line(fd, "READY\n") < 0) goto done;

    /* --- Receive PRESS commands --- */
    int  press_idx[MAX_BIGRAMS];
    uint32_t press_ms[MAX_BIGRAMS];
    int n_press = 0;
    int n_reject = 0, n_coerce = 0;

    while(1){
        char buf[256];
        if(read_line(fd, buf, sizeof(buf)) < 0){
            printf("[client] %s disconnected early\n", peer);
            goto done;
        }

        if(strcmp(buf, "DONE") == 0) break;

        int idx; unsigned int ms;
        if(sscanf(buf, "PRESS %d %u", &idx, &ms) == 2){
            if(n_press >= g_enroll.n){
                printf("[warn] extra PRESS ignored (already have %d)\n", n_press);
                continue;
            }
            int bi = n_press;

            /* Validate word index */
            if(idx < 0 || idx >= SESSION_WORDS){
                printf("[auth] REJECT: idx=%d out of range\n", idx);
                send_line(fd, "RESULT REJECT\nDETAIL word_idx_out_of_range\n");
                goto done;
            }

            const char *word = WORDS[widx[idx]];
            const char *bg   = g_enroll.bg[bi];

            /* Bigram check */
            int ok_word = word_has_bigram(word, bg);
            printf("[press] bi=%d bg='%s' idx=%d word='%s' both_present=%s ms=%u\n",
                   bi, bg, idx, word, ok_word?"YES":"NO", ms);

            if(!ok_word){
                printf("[auth] REJECT: word '%s' missing letter(s) of bigram '%s'\n",
                       word, bg);
                char msg[128];
                snprintf(msg, sizeof(msg),
                         "RESULT REJECT\nDETAIL bigram_%s_not_in_%s\n", bg, word);
                send_line(fd, msg);
                goto done;
            }

            /* Timing z-score */
            int32_t delta  = (int32_t)ms - (int32_t)g_enroll.mean[bi];
            uint32_t sig   = g_enroll.sigma[bi] > 0 ? g_enroll.sigma[bi] : 1;
            uint32_t z100  = (uint32_t)(abs(delta) * 100 / (int)sig);
            printf("[zscore] bi=%d delta=%+dms z=%.2f  %s\n",
                   bi, delta, z100/100.0,
                   z100>=ZSCORE_COERCE ? "REJECT-zone" :
                   z100>=ZSCORE_AUTH   ? "coerce-zone" : "ok");

            if(z100 >= ZSCORE_COERCE) n_reject++;
            else if(z100 >= ZSCORE_AUTH) n_coerce++;

            press_idx[n_press] = idx;
            press_ms[n_press]  = ms;
            n_press++;
        } else {
            printf("[warn] unknown command: '%s'\n", buf);
        }
    }

    /* Check completeness */
    if(n_press < g_enroll.n){
        printf("[auth] REJECT: only %d/%d presses received\n", n_press, g_enroll.n);
        char msg[64];
        snprintf(msg, sizeof(msg),
                 "RESULT REJECT\nDETAIL incomplete_%d_of_%d\n",
                 n_press, g_enroll.n);
        send_line(fd, msg);
        goto done;
    }

    /* Final verdict */
    char result[128];
    if(n_reject > 0){
        snprintf(result, sizeof(result),
                 "RESULT REJECT\nDETAIL %d_positions_out_of_3sigma\n", n_reject);
        printf("[auth] REJECT — %d bad timings\n", n_reject);
    } else if(n_coerce > 0){
        snprintf(result, sizeof(result),
                 "RESULT COERCE\nDETAIL suspicious_timing_%d_positions\n", n_coerce);
        printf("[auth] COERCE — %d suspicious timings\n", n_coerce);
    } else {
        snprintf(result, sizeof(result),
                 "RESULT AUTH\nDETAIL all_%d_bigrams_verified\n", n_press);
        printf("[auth] AUTH — all %d bigrams OK\n", n_press);
    }
    send_line(fd, result);

done:
    close(fd);
    printf("[client] %s session ended\n\n", peer);
}

/* ================================================================== */
/* Main                                                                 */
/* ================================================================== */
int main(int argc, char **argv){
    int port = 8009;
    if(argc >= 2) port = atoi(argv[1]);

    signal(SIGPIPE, SIG_IGN);

    init_enroll();

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if(srv < 0){ perror("socket"); return 1; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons((uint16_t)port);
    sa.sin_addr.s_addr = INADDR_ANY;

    if(bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0){
        perror("bind"); return 1;
    }
    listen(srv, 8);
    printf("[server] SPTA Bigram Auth listening on 0.0.0.0:%d\n", port);
    printf("[server] phrase='helloworld'  bigrams: he ll ow or ld\n\n");

    while(1){
        struct sockaddr_in ca;
        socklen_t calen = sizeof(ca);
        int fd = accept(srv, (struct sockaddr *)&ca, &calen);
        if(fd < 0){
            if(errno == EINTR) continue;
            perror("accept");
            continue;
        }
        handle_client(fd, &ca);
    }
    return 0;
}
