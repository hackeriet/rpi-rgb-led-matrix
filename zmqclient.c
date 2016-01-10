#include <czmq.h>

static void * client_task (char *server_cert_p, char *private_key_p, char *server_url) {
  // Generate the private key if it does not exist
  struct stat sb;
  if((stat(private_key_p, &sb) == -1)) {
    zcert_t *client_cert = zcert_new ();
    int rc = zcert_save (client_cert, private_key_p);
    assert (rc == 0);
    zcert_destroy (&client_cert);
  }

  // Load server certificate
  zcert_t *server_cert = zcert_load(server_cert_p);
  assert(server_cert);

  //  Load our persistent certificate from disk
  zcert_t *client_cert = zcert_load (private_key_p);
  assert (client_cert);

  //  Create client socket and configure it to use full encryption
  zctx_t *ctx = zctx_new ();
  assert (ctx);
  void *client = zsocket_new (ctx, ZMQ_SUB);
  assert (client);
  zcert_apply (client_cert, client);
  zsocket_set_curve_serverkey (client, zcert_public_txt(server_cert));
  int rc = zsocket_connect (client, server_url);
  assert (rc == 0);
  zsock_set_subscribe(client, "");

  //  Wait for our message, that signals the test was successful
  char *message = zstr_recv (client);
  printf("%s\n", message);
  free (message);

  //  Free all memory we used
  zcert_destroy (&server_cert);
  zcert_destroy (&client_cert);
  zctx_destroy (&ctx);
  return NULL;
}

int main (void) {
  char *private_key_p = "client_cert.txt";
  char *server_cert_p = "server.key";
  char *server_url = "tcp://mccarthy.microdisko.no:5566";

  client_task(server_cert_p, private_key_p, server_url);

  return 0;
}
