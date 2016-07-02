#include <czmq.h>

static zcert_t *server_cert;
static zcert_t *client_cert;
static zctx_t *ctx;

void *zmq_setup (const char *server_cert_p,
                 const char *private_key_p, const char *server_url) {
  // Generate the private key if it does not exist
  struct stat sb;
  if((stat(private_key_p, &sb) == -1)) {
    zcert_t *client_cert = zcert_new ();
    int rc = zcert_save (client_cert, private_key_p);
    assert (rc == 0);
    zcert_destroy (&client_cert);
  }

  // Load server certificate
  server_cert = zcert_load(server_cert_p);
  assert(server_cert);

  //  Load our persistent certificate from disk
  client_cert = zcert_load(private_key_p);
  assert (client_cert);

  //  Create client socket and configure it to use full encryption
  ctx = zctx_new ();
  assert (ctx);
  void *client = zsocket_new (ctx, ZMQ_SUB);
  assert (client);
  zcert_apply (client_cert, client);
  zsocket_set_curve_serverkey (client, zcert_public_txt(server_cert));
  int rc = zsocket_connect (client, server_url);
  assert (rc == 0);
  zsock_set_subscribe(client, "");
  return client;
}

int test (void) {
  char *private_key_p = "client_cert.txt";
  char *server_cert_p = "server.key";
  char *server_url = "tcp://mccarthy.microdisko.no:5566";

  void *client = zmq_setup(server_cert_p, private_key_p, server_url);

  zpoller_t *zpoller = zpoller_new(client);

  while (1) {
    if(zsys_interrupted){
      puts("Interrupted");
      goto done;
    }

    void *active = zpoller_wait(zpoller, 0);
    if (active) {
      char *tag;
      char *msg;
      int n = zstr_recvx(active, &tag, &msg, NULL);
      assert(n == 2);
      printf("%s: %s\n", tag, msg);
      zstr_free(&tag);
      zstr_free(&msg);
    }

    puts("Zzz..");
    sleep(1);
  };

 done:
  zcert_destroy (&server_cert);
  zcert_destroy (&client_cert);
  zctx_destroy (&ctx);


  return 0;
}
