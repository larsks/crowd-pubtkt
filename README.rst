Crowd-Pubtkt
============

Atlassian's Crowd product offers a number of useful features, but the
SSO implementation is somewhat lacking.  This application acts as a proxy
between Crowd and mod_auth_pubtkt, offering, if not the best of both
worlds, at least a useful solution.

Authentication model
====================

Authentication to this Application is handled by Apache using the Crowd
connector (mod_authnz_crowd).  After a successful authentication, this
application will (a) attempt to query Crowd for group memberships for the
current user and (b) generate the necessary mod_auth_pubtkt token for
authenticating against mod_auth_tkt enabled sites.

