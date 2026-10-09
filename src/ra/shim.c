/*
 * A flat C face on rcheevos for src/ra/ffi.rs: rc_client's structs and
 * callbacks stay on this side, Rust sees integers, strings and a few function
 * pointers. Everything here runs on the RA thread; the only thing another
 * thread ever does is HTTP, whose answer comes back through ra_http_done().
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "rc_client.h"
#include "rc_hash.h"
#include "rc_runtime.h"
#include "rc_runtime_types.h"
#include "rc_api_runtime.h"
#include "rc_consoles.h"

/* ------------------------------------------------------------------ host */

enum {
    RA_EV_ACHIEVEMENT = 1, RA_EV_LB_STARTED, RA_EV_LB_FAILED, RA_EV_LB_SUBMITTED,
    RA_EV_PROGRESS, RA_EV_COMPLETED, RA_EV_SERVER_ERROR, RA_EV_DISCONNECTED,
    RA_EV_RECONNECTED, RA_EV_RESET, RA_EV_GAME_SETS, RA_EV_HASH_GAME
};
enum { RA_DONE_LOGIN = 1, RA_DONE_LOAD, RA_DONE_MEDIA };

typedef struct ra_host {
    void *ud;
    uint32_t (*read)(void *ud, uint32_t addr, uint8_t *buf, uint32_t n);
    void (*http)(void *ud, uint64_t token, const char *url, const char *post,
                 const char *ctype);
    void (*event)(void *ud, int kind, uint32_t id, uint32_t points,
                  const char *a, const char *b);
    void (*log)(void *ud, const char *msg);
    void (*done)(void *ud, int what, int result, const char *msg);
    /* disc, for the hash: 2048 bytes of one sector, 0 on failure */
    size_t (*sector)(void *ud, uint32_t lba, uint8_t *buf, size_t n);
    /* first sector of the filesystem space of `track` (3, or -1 = first data
     * track), or -1 if the disc has no such track */
    int64_t (*track_first)(void *ud, uint32_t track);
} ra_host;

typedef struct ra_ctx {
    ra_host host;
    rc_client_t *client;
    char *sets;          /* the last game-sets response, for the probe */
    size_t sets_len;
} ra_ctx;

typedef struct ra_pending {
    rc_client_server_callback_t cb;
    void *cbdata;
    int capture;	/* the game's sets: kept for the probe */
    int hash_lookup;	/* "which game is this hash": reported, a media change needs it */
} ra_pending;

static uint32_t read_cb(uint32_t address, uint8_t *buffer, uint32_t num_bytes,
                        rc_client_t *client)
{
    ra_ctx *c = (ra_ctx *)rc_client_get_userdata(client);
    return c->host.read(c->host.ud, address, buffer, num_bytes);
}

static void server_call(const rc_api_request_t *req, rc_client_server_callback_t cb,
                        void *cbdata, rc_client_t *client)
{
    ra_ctx *c = (ra_ctx *)rc_client_get_userdata(client);
    ra_pending *p = (ra_pending *)malloc(sizeof(*p));
    p->cb = cb;
    p->cbdata = cbdata;
    p->capture = req->post_data && strstr(req->post_data, "r=achievementsets");
    p->hash_lookup = req->post_data && strstr(req->post_data, "r=gameid");
    c->host.http(c->host.ud, (uint64_t)(uintptr_t)p, req->url, req->post_data,
                 req->content_type);
}

void ra_http_done(ra_ctx *c, uint64_t token, int status, const char *body, size_t len)
{
    ra_pending *p = (ra_pending *)(uintptr_t)token;
    rc_api_server_response_t r;

    if (p->capture && status == 200 && body) {
        free(c->sets);
        c->sets = (char *)malloc(len + 1);
        memcpy(c->sets, body, len);
        c->sets[len] = 0;
        c->sets_len = len;
        c->host.event(c->host.ud, RA_EV_GAME_SETS, 0, 0, NULL, NULL);
    }
    r.body = body;
    r.body_length = len;
    r.http_status_code = status;
    if (p->hash_lookup && status == 200 && body) {
        rc_api_resolve_hash_response_t g;

        if (rc_api_process_resolve_hash_server_response(&g, &r) == RC_OK)
            c->host.event(c->host.ud, RA_EV_HASH_GAME, g.game_id, 0, NULL, NULL);
        rc_api_destroy_resolve_hash_response(&g);
    }
    p->cb(&r, p->cbdata);
    free(p);
}

const char *ra_game_sets(ra_ctx *c, size_t *len)
{
    *len = c->sets_len;
    return c->sets;
}

static void event_cb(const rc_client_event_t *e, rc_client_t *client)
{
    ra_ctx *c = (ra_ctx *)rc_client_get_userdata(client);
    void *ud = c->host.ud;

    switch (e->type) {
    case RC_CLIENT_EVENT_ACHIEVEMENT_TRIGGERED:
        c->host.event(ud, RA_EV_ACHIEVEMENT, e->achievement->id, e->achievement->points,
                      e->achievement->title, e->achievement->description);
        break;
    case RC_CLIENT_EVENT_LEADERBOARD_STARTED:
        c->host.event(ud, RA_EV_LB_STARTED, e->leaderboard->id, 0, e->leaderboard->title,
                      e->leaderboard->description);
        break;
    case RC_CLIENT_EVENT_LEADERBOARD_FAILED:
        c->host.event(ud, RA_EV_LB_FAILED, e->leaderboard->id, 0, e->leaderboard->title, NULL);
        break;
    case RC_CLIENT_EVENT_LEADERBOARD_SUBMITTED:
        c->host.event(ud, RA_EV_LB_SUBMITTED, e->leaderboard->id, 0, e->leaderboard->title,
                      NULL);
        break;
    case RC_CLIENT_EVENT_ACHIEVEMENT_PROGRESS_INDICATOR_SHOW:
    case RC_CLIENT_EVENT_ACHIEVEMENT_PROGRESS_INDICATOR_UPDATE:
        c->host.event(ud, RA_EV_PROGRESS, e->achievement->id, 0, e->achievement->title,
                      e->achievement->measured_progress);
        break;
    case RC_CLIENT_EVENT_GAME_COMPLETED:
        c->host.event(ud, RA_EV_COMPLETED, 0, 0, NULL, NULL);
        break;
    case RC_CLIENT_EVENT_SERVER_ERROR:
        c->host.event(ud, RA_EV_SERVER_ERROR, 0, 0, e->server_error->api,
                      e->server_error->error_message);
        break;
    case RC_CLIENT_EVENT_DISCONNECTED:
        c->host.event(ud, RA_EV_DISCONNECTED, 0, 0, NULL, NULL);
        break;
    case RC_CLIENT_EVENT_RECONNECTED:
        c->host.event(ud, RA_EV_RECONNECTED, 0, 0, NULL, NULL);
        break;
    case RC_CLIENT_EVENT_RESET:
        c->host.event(ud, RA_EV_RESET, 0, 0, NULL, NULL);
        break;
    default:
        break;
    }
}

static void log_cb(const char *message, const rc_client_t *client)
{
    ra_ctx *c = (ra_ctx *)rc_client_get_userdata((rc_client_t *)client);
    c->host.log(c->host.ud, message);
}

ra_ctx *ra_new(const ra_host *host, int hardcore)
{
    ra_ctx *c = (ra_ctx *)calloc(1, sizeof(*c));

    c->host = *host;
    c->client = rc_client_create(read_cb, server_call);
    rc_client_set_userdata(c->client, c);
    rc_client_set_event_handler(c->client, event_cb);
    rc_client_set_hardcore_enabled(c->client, hardcore);
    rc_client_set_allow_background_memory_reads(c->client, 1);
    rc_client_enable_logging(c->client, RC_CLIENT_LOG_LEVEL_WARN, log_cb);
    return c;
}

/* A different server (tests: a local fake). NULL keeps retroachievements.org. */
void ra_set_host(ra_ctx *c, const char *host)
{
    rc_client_set_host(c->client, host);
}

void ra_destroy(ra_ctx *c)
{
    rc_client_destroy(c->client);
    free(c->sets);
    free(c);
}

size_t ra_user_agent_clause(ra_ctx *c, char *buf, size_t n)
{
    return rc_client_get_user_agent_clause(c->client, buf, n);
}

/* ------------------------------------------------------- login, game, frame */

static void done_login(int result, const char *msg, rc_client_t *client, void *ud)
{
    ra_ctx *c = (ra_ctx *)ud;
    (void)client;
    c->host.done(c->host.ud, RA_DONE_LOGIN, result, msg);
}

static void done_load(int result, const char *msg, rc_client_t *client, void *ud)
{
    ra_ctx *c = (ra_ctx *)ud;
    (void)client;
    c->host.done(c->host.ud, RA_DONE_LOAD, result, msg);
}

void ra_login_password(ra_ctx *c, const char *user, const char *password)
{
    rc_client_begin_login_with_password(c->client, user, password, done_login, c);
}

void ra_login_token(ra_ctx *c, const char *user, const char *token)
{
    rc_client_begin_login_with_token(c->client, user, token, done_login, c);
}

/* After a password login: the token to store, valid while the client lives. */
const char *ra_token(ra_ctx *c)
{
    const rc_client_user_t *u = rc_client_get_user_info(c->client);
    return u ? u->token : NULL;
}

const char *ra_display_name(ra_ctx *c)
{
    const rc_client_user_t *u = rc_client_get_user_info(c->client);
    return u ? u->display_name : NULL;
}

void ra_load_game(ra_ctx *c, const char *hash)
{
    rc_client_begin_load_game(c->client, hash, done_load, c);
}

/* A multi-disc game's next disc. rc_client keeps the game loaded and only notes the
 * new media's hash (it never loads another game: that is unload + load); a hash it
 * has not seen is looked up first, which RA_EV_HASH_GAME reports. */
static void done_media(int result, const char *msg, rc_client_t *client, void *ud)
{
    ra_ctx *c = (ra_ctx *)ud;
    (void)client;
    c->host.done(c->host.ud, RA_DONE_MEDIA, result, msg);
}

void ra_change_media(ra_ctx *c, const char *hash)
{
    rc_client_begin_change_media(c->client, hash, done_media, c);
}

void ra_unload_game(ra_ctx *c)
{
    rc_client_unload_game(c->client);
}

/* Title and id of the loaded game, 0 when none. */
uint32_t ra_game_id(ra_ctx *c, const char **title)
{
    const rc_client_game_t *g = rc_client_get_game_info(c->client);
    if (!g)
        return 0;
    *title = g->title;
    return g->id;
}

/* The loaded game's badge, a URL; NULL when none. */
const char *ra_game_badge(ra_ctx *c)
{
    const rc_client_game_t *g = rc_client_get_game_info(c->client);
    return g ? g->badge_url : NULL;
}

/* What the user already has of the loaded game, in the session's mode:
 * rc_client does not watch an earned achievement again. */
void ra_game_summary(ra_ctx *c, uint32_t *core, uint32_t *unlocked,
                     uint32_t *unsupported, int *hardcore)
{
    rc_client_user_game_summary_t s;
    rc_client_get_user_game_summary(c->client, &s);
    *core = s.num_promoted_achievements;
    *unlocked = s.num_unlocked_achievements;
    *unsupported = s.num_unsupported_achievements;
    *hardcore = rc_client_get_hardcore_enabled(c->client);
}

/* Each promoted (core) achievement with rc_client's state
 * (RC_CLIENT_ACHIEVEMENT_STATE_*). */
void ra_each_achievement(ra_ctx *c, void *ud,
                         void (*cb)(void *ud, uint32_t id, int state, const char *title))
{
    rc_client_achievement_list_t *l = rc_client_create_achievement_list(c->client,
        RC_CLIENT_ACHIEVEMENT_CATEGORY_PROMOTED, RC_CLIENT_ACHIEVEMENT_LIST_GROUPING_LOCK_STATE);
    if (!l)
        return;
    for (uint32_t b = 0; b < l->num_buckets; b++)
        for (uint32_t i = 0; i < l->buckets[b].num_achievements; i++) {
            const rc_client_achievement_t *a = l->buckets[b].achievements[i];
            cb(ud, a->id, a->state, a->title);
        }
    rc_client_destroy_achievement_list(l);
}

void ra_do_frame(ra_ctx *c) { rc_client_do_frame(c->client); }
void ra_idle(ra_ctx *c) { rc_client_idle(c->client); }
void ra_reset(ra_ctx *c) { rc_client_reset(c->client); }

size_t ra_rich_presence(ra_ctx *c, char *buf, size_t n)
{
    return rc_client_get_rich_presence_message(c->client, buf, n);
}

/* ------------------------------------------------------------------ hash */

typedef struct ra_track {
    const rc_hash_iterator_t *it;
    int64_t first;
} ra_track;

static void *cd_open(const char *path, uint32_t track,
                     const struct rc_hash_iterator *it)
{
    ra_ctx *c = (ra_ctx *)it->userdata;
    int64_t first = c->host.track_first(c->host.ud, track);
    ra_track *t;

    (void)path;
    if (first < 0)
        return NULL;
    t = (ra_track *)malloc(sizeof(*t));
    t->it = it;
    t->first = first;
    return t;
}

static size_t cd_read(void *h, uint32_t sector, void *buffer, size_t requested)
{
    ra_track *t = (ra_track *)h;
    ra_ctx *c = (ra_ctx *)t->it->userdata;
    uint8_t tmp[2048];
    size_t got = c->host.sector(c->host.ud, sector, tmp, sizeof(tmp));

    if (got > requested)
        got = requested;
    memcpy(buffer, tmp, got);
    return got;
}

static void cd_close(void *h) { free(h); }
static uint32_t cd_first(void *h) { return (uint32_t)((ra_track *)h)->first; }

int ra_hash_dreamcast(ra_ctx *c, char out[33])
{
    rc_hash_iterator_t it;
    int ok;

    rc_hash_initialize_iterator(&it, "disc", NULL, 0);
    it.userdata = c;
    it.callbacks.cdreader.open_track = NULL;
    it.callbacks.cdreader.open_track_iterator = cd_open;
    it.callbacks.cdreader.read_sector = cd_read;
    it.callbacks.cdreader.close_track = cd_close;
    it.callbacks.cdreader.first_track_sector = cd_first;
    ok = rc_hash_generate(out, RC_CONSOLE_DREAMCAST, &it);
    rc_hash_destroy_iterator(&it);
    return ok;
}

/* ----------------------------------------------------------------- probe */

/*
 * Which words does this set read? A second, private runtime holds every
 * achievement, leaderboard and the rich presence of the game and is run on
 * the console's memory a frame ahead of the real client: whatever it reads
 * that the table lacks is what the table must grow by, and the frame is not
 * given to the real client until it does not. Its triggers are deactivated by
 * the engine when they fire and put back here; nothing it does leaves the
 * process.
 */
typedef struct ra_probe {
    rc_runtime_t rt;
    uint32_t *ach_ids;
    char **ach_defs;
    uint32_t *lb_ids;
    uint32_t n_ach, n_lb;
    uint32_t *fired;
    uint32_t n_fired, cap_fired;
    int has_rp;
    uint32_t frame;
} ra_probe;

/* rc_runtime_do_frame()'s event handler takes no user data, so the probe being run
 * is passed through this. One per thread: the host runs a single RA thread, tests
 * run several probes at once. */
#if defined(_MSC_VER)
#define RA_TLS __declspec(thread)
#else
#define RA_TLS _Thread_local
#endif
static RA_TLS ra_probe *g_probe;

static void probe_event(const rc_runtime_event_t *e)
{
    ra_probe *p = g_probe;

    if (e->type == RC_RUNTIME_EVENT_ACHIEVEMENT_TRIGGERED && p->n_fired < p->cap_fired)
        p->fired[p->n_fired++] = e->id;
}

ra_probe *ra_probe_new(const char *json, size_t len)
{
    rc_api_fetch_game_sets_response_t r;
    rc_api_server_response_t sr;
    ra_probe *p;
    uint32_t s, i, total = 0;

    sr.body = json;
    sr.body_length = len;
    sr.http_status_code = 200;
    if (rc_api_process_fetch_game_sets_server_response(&r, &sr) != RC_OK
        || !r.response.succeeded) {
        rc_api_destroy_fetch_game_sets_response(&r);
        return NULL;
    }
    for (s = 0; s < r.num_sets; s++)
        total += r.sets[s].num_achievements;

    p = (ra_probe *)calloc(1, sizeof(*p));
    rc_runtime_init(&p->rt);
    p->ach_ids = (uint32_t *)calloc(total + 1, sizeof(uint32_t));
    p->ach_defs = (char **)calloc(total + 1, sizeof(char *));
    p->fired = (uint32_t *)calloc(total + 1, sizeof(uint32_t));
    p->cap_fired = total + 1;
    {
        uint32_t nl = 0;
        for (s = 0; s < r.num_sets; s++)
            nl += r.sets[s].num_leaderboards;
        p->lb_ids = (uint32_t *)calloc(nl + 1, sizeof(uint32_t));
    }

    for (s = 0; s < r.num_sets; s++) {
        for (i = 0; i < r.sets[s].num_achievements; i++) {
            const rc_api_achievement_definition_t *a = &r.sets[s].achievements[i];
            size_t n = strlen(a->definition) + 1;

            p->ach_ids[p->n_ach] = a->id;
            p->ach_defs[p->n_ach] = (char *)malloc(n);
            memcpy(p->ach_defs[p->n_ach], a->definition, n);
            if (rc_runtime_activate_achievement(&p->rt, a->id, a->definition, NULL, 0) == RC_OK)
                p->n_ach++;
            else
                free(p->ach_defs[p->n_ach]);
        }
        for (i = 0; i < r.sets[s].num_leaderboards; i++) {
            const rc_api_leaderboard_definition_t *l = &r.sets[s].leaderboards[i];

            if (rc_runtime_activate_lboard(&p->rt, l->id, l->definition, NULL, 0) == RC_OK)
                p->lb_ids[p->n_lb++] = l->id;
        }
    }
    if (r.rich_presence_script && r.rich_presence_script[0])
        p->has_rp = rc_runtime_activate_richpresence(&p->rt, r.rich_presence_script, NULL, 0) == RC_OK;
    rc_api_destroy_fetch_game_sets_response(&r);
    return p;
}

void ra_probe_counts(const ra_probe *p, uint32_t *ach, uint32_t *lb, int *rp)
{
    *ach = p->n_ach;
    *lb = p->n_lb;
    *rp = p->has_rp;
}

void ra_probe_frame(ra_probe *p, rc_runtime_read_memory_func_t peek, void *ud)
{
    uint32_t i, j;
    char rp[256];

    g_probe = p;
    p->n_fired = 0;
    rc_runtime_do_frame(&p->rt, probe_event, peek, ud, NULL);
    /* Put back what fired, so its pointers keep being followed. */
    for (i = 0; i < p->n_fired; i++) {
        for (j = 0; j < p->n_ach; j++) {
            if (p->ach_ids[j] == p->fired[i]) {
                rc_runtime_deactivate_achievement(&p->rt, p->fired[i]);
                rc_runtime_activate_achievement(&p->rt, p->fired[i], p->ach_defs[j], NULL, 0);
                break;
            }
        }
    }
    /* The rich presence reads memory only when it is asked for. */
    if (p->has_rp && (p->frame++ % 30U) == 0)
        rc_runtime_get_richpresence(&p->rt, rp, sizeof(rp), peek, ud, NULL);
}

void ra_probe_free(ra_probe *p)
{
    uint32_t i;

    if (!p)
        return;
    rc_runtime_destroy(&p->rt);
    for (i = 0; i < p->n_ach; i++)
        free(p->ach_defs[i]);
    free(p->ach_ids);
    free(p->lb_ids);
    free(p->ach_defs);
    free(p->fired);
    free(p);
}

/* ------------------------------------------------------------ pointer walk */

/*
 * WHERE THE SET READS, FROM THE PUBLIC STRUCTURES ONLY (rc_runtime_types.h):
 * rc_runtime_get_achievement() / rc_runtime_get_lboard() give triggers, a trigger
 * its condition sets, a condition its two operands, an operand its memref
 * (address, size) -- nothing from rc_internal.h.
 *
 * AddAddress is what makes a read indirect, and its meaning is documented: the
 * value it reads is added to the address of the next condition's memory operands
 * (and of a following AddAddress, which is how chains nest). So position decides:
 * after an AddAddress, a memref operand's `address` is an OFFSET from that
 * accumulated pointer, not an address. (`ra_probe_walk` is covered by a test that
 * fails if a rcheevos update changes what those fields hold.)
 *
 * Events, to the callback (ud, kind, node, parent, value, bytes):
 *   1 root pointer: read `bytes` at absolute address `value`; new node `node`
 *   2 pointer inside a pointer: at (value of `parent`) + offset `value`; new `node`
 *   3 indirect read of `bytes` at (value of `parent`) + offset `value`
 *   4 direct read of `bytes` at absolute address `value`
 *   5 a construct this walk does not model (a pointer that is not 24 bits, one
 *     with no parent where it needs one): its reads stay for discovery
 */
typedef void (*ra_walk_cb)(void *ud, int kind, int node, int parent, uint32_t value,
                           uint32_t bytes);

static uint32_t walk_bytes(uint8_t size)
{
    switch (size) {
    case RC_MEMSIZE_16_BITS: case RC_MEMSIZE_16_BITS_BE: return 2;
    case RC_MEMSIZE_24_BITS: case RC_MEMSIZE_24_BITS_BE: return 3;
    case RC_MEMSIZE_32_BITS: case RC_MEMSIZE_32_BITS_BE: case RC_MEMSIZE_FLOAT:
    case RC_MEMSIZE_FLOAT_BE: case RC_MEMSIZE_MBF32: case RC_MEMSIZE_MBF32_LE:
    case RC_MEMSIZE_DOUBLE32: case RC_MEMSIZE_DOUBLE32_BE: return 4;
    default: return 1;	/* 8 bits, nibbles, single bits, bit count */
    }
}

static void walk_operand(const rc_operand_t *op, int acc, ra_walk_cb cb, void *ud)
{
    if (!rc_operand_is_memref(op))
        return;
    if (acc >= 0)
        cb(ud, 3, -1, acc, op->value.memref->address, walk_bytes(op->size));
    else if (acc == -1)
        cb(ud, 4, -1, -1, op->value.memref->address, walk_bytes(op->size));
    else
        cb(ud, 5, -1, -1, 0, 0);
}

static void walk_condset(const rc_condset_t *cs, int *next, ra_walk_cb cb, void *ud)
{
    for (; cs; cs = cs->next) {
        const rc_condition_t *c;
        int acc = -1;		/* -1 none, -2 poisoned, else a node id */

        for (c = cs->conditions; c; c = c->next) {
            if (c->type == RC_CONDITION_ADD_ADDRESS) {
                const rc_operand_t *op = &c->operand1;
                int node;

                if (!rc_operand_is_memref(op) || op->size != RC_MEMSIZE_24_BITS || acc == -2) {
                    cb(ud, 5, -1, -1, 0, 0);
                    acc = -2;
                    continue;
                }
                node = (*next)++;
                if (acc >= 0)
                    cb(ud, 2, node, acc, op->value.memref->address, 3);
                else
                    cb(ud, 1, node, -1, op->value.memref->address, 3);
                acc = node;
            } else {
                walk_operand(&c->operand1, acc, cb, ud);
                walk_operand(&c->operand2, acc, cb, ud);
                acc = -1;
            }
        }
    }
}

static void walk_trigger(const rc_trigger_t *t, int *next, ra_walk_cb cb, void *ud)
{
    walk_condset(t->requirement, next, cb, ud);
    walk_condset(t->alternative, next, cb, ud);
}

/* One value, and only that: `rc_value_t.next` chains the named variables of a rich
 * presence script, and an lboard's own value and progress are not part of such a
 * chain -- their `next` is not meaningful, and following it crashed (found under
 * a parallel test run). The condition sets of one value ARE a chain of candidates
 * (the largest wins), which walk_condset follows. */
static void walk_value(const rc_value_t *v, int *next, ra_walk_cb cb, void *ud)
{
    if (v)
        walk_condset(v->conditions, next, cb, ud);
}

/* The rich presence: each display's own condition, and the script's named values,
 * which ARE a chain through `next`. The memory operands of the display PARTS are
 * left out: whether a part holds one is told by `display_type`, whose values are
 * not public, and reading one that holds text crashed. A part with an indirect
 * read keeps it in a named value; a plain one is found by discovery. */
static void walk_richpresence(const rc_richpresence_t *rp, int *next, ra_walk_cb cb, void *ud)
{
    const rc_richpresence_display_t *d;
    const rc_value_t *v;

    for (d = rp->first_display; d; d = d->next)
        walk_trigger(&d->trigger, next, cb, ud);
    for (v = rp->values; v; v = v->next)
        walk_condset(v->conditions, next, cb, ud);
}

void ra_probe_walk(ra_probe *p, ra_walk_cb cb, void *ud)
{
    uint32_t i;
    int next = 0;

    for (i = 0; i < p->n_ach; i++) {
        const rc_trigger_t *t = rc_runtime_get_achievement(&p->rt, p->ach_ids[i]);
        if (t)
            walk_trigger(t, &next, cb, ud);
    }
    for (i = 0; i < p->n_lb; i++) {
        const rc_lboard_t *l = rc_runtime_get_lboard(&p->rt, p->lb_ids[i]);
        if (!l)
            continue;
        walk_trigger(&l->start, &next, cb, ud);
        walk_trigger(&l->submit, &next, cb, ud);
        walk_trigger(&l->cancel, &next, cb, ud);
        walk_value(&l->value, &next, cb, ud);
        walk_value(l->progress, &next, cb, ud);
    }
    if (p->rt.richpresence && p->rt.richpresence->richpresence)
        walk_richpresence(p->rt.richpresence->richpresence, &next, cb, ud);
}
