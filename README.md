Openfire Extended LDAP User Provider
====================================

An Openfire UserProvider to better support ldap repositories which don't have a full name field available.

Installation
------------
1 mvn package

2 Copy the jar-with-dependencies jar file into the openfire/lib directory.

3 Add or update the following Openfire server property:
    provider.user.className = com.surevine.chat.openfire.ldap.ExtendedLdapUserProvider

4 restart Openfire


Configuration
-------------
The provider can be configured using the normal Openfire ldap configuration
and also 

### ldap.displayNameTemplate
A template to use for the user's xmpp display (nick) name. Replacements can be made by enclosing ldap attributes names in curly braces.

> For example: "{familyName} {sn}"

### ldap.seperateSearchTerms
If this property is set to "true", then search string will be split into separate search terms (on whitespace)

> For example: A search for "some thing" will search for "some" AND "thing"

### ldap.searchNameFields
Comma separated set of fields which will be searched through if a query for "Name" is received. Note these should be the XMPP field names, not the ldap field names (as defined in ldap.searchFields).

> For example: If you have the following set for ldap.searchFields:
>     "Username/uid,Name/uid,Email/mail,Given Name/givenName,Family Name/sn"
> Then you might want to set ldap.searchNameFields to
>     "Given Name,Family Name,Username"