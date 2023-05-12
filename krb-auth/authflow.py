import krb5
import logging
import os
import socket
import sys

logging.basicConfig(level=logging.INFO)

ctx = krb5.Krb5Context()

username = "thunder@thunder"  # these are not used anywhere in the world hahahaha
password = "Thunder1"

try:

    ccache = ctx.default_ccache() # create a local cache for carrying it to the kdc

    logging.info("Authenticating user %s with KDC", username)
    try:
        creds = ctx.get_init_creds_password(username, password, ccache)
    except krb5.Krb5Error as e:
        logging.error("Kerberos authentication error: %s", e)
        sys.exit(1)

    logging.info("Getting service ticket for user %s", username) # cool getting the service ticket.
    server_princ = krb5.Principal("host/kerberos.thunder.com")
    try:
        server_creds = creds.get_service_ticket(server_princ)
    except krb5.Krb5Error as e:
        logging.error("Error getting service ticket: %s", e)
        sys.exit(1)

    # kumbuka we imported socket libraries..now we use it here.
    logging.info("Checking hostname of local machine")
    try:
        hostname = socket.gethostname()
        logging.info("Hostname of local machine is %s", hostname)
    except OSError as e:
        logging.error("Error getting hostname: %s", e)
# just as the way browsers store cache information then thats not a difference here.
    logging.info("Checking for test file on local machine")
    try:
        with open("thunder@thunder.txt", "w") as f:
            f.write("text file found")
        if os.path.isfile("thunder@thunder.txt"):
            logging.info("Test file exists")
        else:
            logging.error("Test file does not exist")
    except OSError as e:
        logging.error("Error accessing test file: %s", e)

    logging.info("Service ticket obtained for %s", username)
    logging.info("Ticket information:\n%s", server_creds)

    os.remove("testfile.txt") # remember clearing browser cache files..this one does for you
    # seems krb is fun right :-)

except krb5.Krb5Error as e:
    logging.error("Kerberos error: %s", e)
    sys.exit(1)

logging.info("Kerberos authentication successful") # enjoy your service now 

# :-)
