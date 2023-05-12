import krb5
import logging
import sys
import socket
import os

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)  # start of the krb logging

try:
    context = krb5.Context()
except krb5.Krb5Error as e:
    logging.error(f"Error setting up Kerberos context: {e}")
    sys.exit(1)
try:
    creds = context.get_init_creds_password("thunder@thunder", "Thunder1")
except krb5.Krb5Error as e:
    logging.error(f"Error requesting TGT: {e}")
    sys.exit(1)

try:
    context.verify_creds(creds, "thunder@thunder", None)
except krb5.Krb5Error as e:
    logging.error(f"Error verifying TGT: {e}")
    sys.exit(1)

session_key = creds.session_key.contents
try:
    service_principal = krb5.Principal("service@REALM")
    service_ticket = context.get_service_ticket(creds, service_principal)
except krb5.Krb5Error as e:
    logging.error(f"Error requesting service ticket: {e}")
    sys.exit(1)

try:
    context.verify_ticket(service_ticket, None, creds, service_principal, None, None)
except krb5.Krb5Error as e:
    logging.error(f"Error verifying service ticket: {e}")
    sys.exit(1)
service_session_key = service_ticket.session_key.contents

plaintext = "Hello, world!" # encrypting the session keys provided from the kdc
encrypted_plaintext = krb5.crypt(plaintext, session_key, direction=krb5.EncryptDirection.ENCRYPT)
decrypted_plaintext = krb5.crypt(encrypted_plaintext, service_session_key, direction=krb5.EncryptDirection.DECRYPT)

try:
    client_authenticator = krb5.Authenticator(context=context, client=creds.client, subkey=None, seq_number=None, checksum=None, cksumtype=None, authenticator=None)
    service_authenticator = krb5.Authenticator(context=context, client=creds.client, subkey=None, seq_number=None, checksum=None, cksumtype=None, authenticator=None)
    client_authenticator_seqnum = context.generate_seq_number()
    client_authenticator.ctime = context.timeofday()
    client_authenticator.cusec = context.microsecond()
    client_authenticator.seq_number = client_authenticator_seqnum
    client_authenticator.authorization_data = None
    service_authenticator.ctime = context.timeofday()
    service_authenticator.cusec = context.microsecond()
    service_authenticator.seq_number = client_authenticator_seqnum
    service_authenticator.authorization_data = None
    context.verify_ap_req(service_ticket, creds, client_authenticator, service_authenticator, None)
except krb5.Krb5Error as e:
    logging.error(f"Error creating or verifying authenticator: {e}")
    sys.exit(1)
# checks the hostname of the local machine 
# might be maybe the domain controller.

try:
    hostname = socket.gethostname()
    logging.info(f"Hostname: {hostname}")
except socket.error as e:
    logging.error(f"Error getting hostname: {e}")
    sys.exit(1)
# well still i've some section not getting debugged
# if it doesnt work then cry :-) anyway kidding.. 
# i am developing more 
   
