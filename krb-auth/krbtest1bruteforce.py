import socket
# active directory pen testers small help tu 
# might not be enugh still in development phase
# first thing am not teaching anyone crime 
# this is just for education purpose 
# not perfect but try integrating it to your development lab.
# dont try this in pblic servers without being authorised
# If not perfect opn a pull request and colaborate 
# using thunder@thunder and Thunder1 as the default credentials too 
# bes ure of the ip address of your kdc server 
# ensure at the port number you replace with the one used by the kdc server in your lab environment 
def test_credentials(username, password):
  # this 127.0.0.1 ive used it as a axample
    KDC_IP = '127.0.0.1'
    # ive also used this port as an example 
    KDC_PORT = 88

    
    # sedning the AS which means (authentication service) to TGT (ticket graniting ticket) 
    # in the AS-REQ ther is ussually the identity of the client and the name of the kerberos realm that you using in your lab environment
    as_req = construct_as_req(username)

    # this section we senf the as-req to the kdc server,,ensure that the kdc server is active..you can do this by pingign it using the ping <ip address of kdc server>
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(as_req, (KDC_IP, KDC_PORT))

        # REsponse from the kdc server ussually known as TGS-REP
        # TGS-REP contains the requested servcie ticket which in this case we receied from the kdc server
        as_rep, _ = s.recvfrom(4096)
# now that we have the response from the kdc server we are going to parse it so that we can get the ticket by extracting it 
    tgt = extract_tgt(as_rep)

    # Construction of the TGS-REQ.
    
    # this is a message ussually is mainly fro requesting the service ticket.
    tgs_req = construct_tgs_req(tgt, 'krbtgt/<ipaddress>.COM', 'ldap/<ipaddress>.COM')

    # request to the kdc server and the response respectively.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(tgs_req, (KDC_IP, KDC_PORT))
        tgs_rep, _ = s.recvfrom(4096)

    # Parse the TGS-REP message and extract the service ticket
    service_ticket = extract_service_ticket(tgs_rep)

    # Construction of the the AP-REQ message 
    # all these are important steps to harden authentication
    ap_req = construct_ap_req(service_ticket, username)

    # Send the AP-REQ message to the service server
    # this local host you need to change it to your krb server ip address 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('127.0.0.1', 389)) # Replace with the IP address of your service server and port number
        s.sendall(ap_req)

        # Receive the AP-REP message from the service server
        ap_rep = s.recv(4096)

    # now this will be parsed i:e the AP-REP message and then verified if the credentials are tue and valid 
    if verify_ap_rep(ap_rep, service_ticket, password):
        print('Nice these are valid credentials')
    else:
        print('invalid credentials you /no bruteforcing here')
