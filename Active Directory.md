- Directory Service used to managed Windows networks.
- Stores information about objects on the network and makes it easily available to users and admins.
- "Active Directory enables centralized, secure management of an entire network, which might span a building, a city or multiple locations throughout the world."

![[Active Directory.png]]

### Active Directory - Components
- Schema - Defines objects and their attributes.
- Query and index mechanism - Provides searching and publication of objects and their properties.
- Global Catalog - Contains information about every object in the directory. Every domain controller have it's own global catalog
- Replication Service - Distributes information across domain controllers
### Active Directory - Structure
- Forests, domains and organizational units (OUs) are the basic building blocks of any active directory structure.
- A forest - which is a security boundary - may contain multiple domains and each domain may contain multiple OUs.
- With in the forest if a single domain is compromised the entire forest is compromised
- Within a forest all domain have trust between each other
![[forest.png]]
