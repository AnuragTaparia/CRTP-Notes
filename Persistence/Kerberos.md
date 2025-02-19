- Kerberos is the basis of authentication in a Windows Active Directory environment. 
- Clients (programs on behalf of a user) need to obtain tickets from Key Distribution Center (KDC) which is a service running on the domain controller. These tickets represent the client's credentials.! 
-  Therefore, Kerberos is understandably a very interesting target of abuse!
- TGT takes take care of authentication and TGS takes care of authorization
- If SPN(it is an attribute on account name) is there for an account you can request it’s TGS
- Only validation KDC/DC does at the end of step 3 is that weather it can decrypt the TGT or not
![[Kerberos.png]]
