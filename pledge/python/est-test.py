import est.client

host = 'testrfc7030.cisco.com'
port = 8443
implicit_trust_anchor_cert_path = 'server.pem'

client = est.client.Client(host, port, implicit_trust_anchor_cert_path)

# Get CSR attributes from EST server as an OrderedDict.
csr_attrs = client.csrattrs()

# Get EST server CA certs.
ca_certs = client.cacerts()

username = 'estuser'
password = 'estpwd'
client.set_basic_auth(username, password)

# Create CSR and get private key used to sign the CSR.
common_name = 'test'
country = 'US'
state = 'Massachusetts'
city = 'Boston'
organization = 'Cisco Systems'
organizational_unit = 'ENG'
email_address = 'test@cisco.com'
priv, csr = client.create_csr(common_name, country, state, city,
                                     organization, organizational_unit,
                                     email_address)

# Enroll: get cert signed by the EST server.
client_cert = client.simpleenroll(csr)

# Re-Enroll: Renew cert.  The previous cert/key can be passed for auth if needed.
client_cert = client.simplereenroll(csr)
