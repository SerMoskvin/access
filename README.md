# Package "**Access**"

> [!NOTE]
> This package use "*github.com/golang-jwt/jwt/v4*", "*golang.org/x/crypto*", "*github.com/go-chi/chi/v5*" for routing endpoints, and "*github.com/stretchr/testify*" for tests.

Provides authentication and authorization of users in the system and transmits the URL depending on the user's role.

## Work start

#### For correct work, you need to create 2 .yml files: 
1. In the first file write jwt characteristics:
- JWT:start secret, rotation period, TTL for jwt-secret, how many old kays to keep in memory;
- System path for your file with permisiion map;
- Cost (number of iterarion) for hash-function;
- Cache: token TTL, password TTL and permission TTL.
2. In the second file write your permission map for every role of user: 
- Name of the role;
- Can this role interact with own records only;
- All avaliable sections for this role (name, URL, can this role read and/or write this section).
>Examples of filling .yml are given in the tests.
