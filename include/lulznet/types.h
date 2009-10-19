typedef struct
{

#define LISTEN_MODE		0x01
#define AUTH_SERVICE		0x02
#define INTERPEER_ACTIVE_MODE	0x04

  int flags;
  short connecting_port;
  short binding_port;
  char *connecting_address;
  char *binding_address;
  char *tap_address;
  char *tap_netmask;
  char *username;
} option_t;

typedef struct
{
  char *user[MAX_PEERS];
  int address[MAX_PEERS];

  int count;
} user_ls_t;

typedef struct
{

  /* XXX: fix remote bof */
  int count;

  char *device[MAX_TAPS];
  int address[MAX_TAPS];
  int network[MAX_TAPS];
  int netmask[MAX_TAPS];

} net_ls_t;

/* This struct holds remote peers informations */
typedef struct
{
  /* related file descriptor */
  int fd;
  SSL *ssl;

  /* peer state (active, closing, ...) */
  char state;

  /* remote peer username and address */
  char *user;
  int address;

  /* peer's lulz device info */
  net_ls_t *nl;

} peer_handler_t;

typedef struct
{
  int fd;
  char flags;
  char *device;
  int address;
  int netmask;
  int network;

  char *allowed_users[MAX_PEERS];
  int allowed_users_count;

} tap_handler_t;


typedef struct
{
  char *peer_username;

  user_ls_t *user_ls;
  net_ls_t *net_ls;
} hs_opt_t;

typedef struct
{
  char command[33];
  char argv[4][128];
  int argc;
} sh_cmd;

