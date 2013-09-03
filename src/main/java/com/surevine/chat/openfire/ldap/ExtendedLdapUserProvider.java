/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * This is a modification of the original LdapUserProvider which is
 * Copyright (C) 2004-2008 Jive Software. All rights reserved.
 * 
 * This was modified by Surevine Ltd.
 * All modifications are (C) 2011 Surevine Ltd.
 */

package com.surevine.chat.openfire.ldap;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.ldap.LdapManager;
import org.jivesoftware.openfire.ldap.LdapUserProvider;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserAlreadyExistsException;
import org.jivesoftware.openfire.user.UserCollection;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.openfire.user.UserProvider;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

/**
 * Extends the {@link LdapUserProvider} to better support ldap repositories
 * which don't have a full name field available.<br />
 * Extra properties are:
 * <dl>
 * <dt>ldap.displayNameTemplate</dt>
 * <dd>A template to use for the user's xmpp display (nick) name. Replacements
 * can be made by enclosing ldap attributes names in curly braces.<br />
 * For example: "{familyName} {sn}"</dd>
 * <dt>ldap.seperateSearchTerms</dt>
 * <dd>If this property is set to "true", then search string will be split into
 * separate search terms (on whitespace)<br />
 * For example: A search for "some thing" will search for "some" AND "thing"</dd>
 * <dt>ldap.searchNameFields</dt>
 * <dd>Comma separated set of fields which will be searched through if a query
 * for "Name" is received. Note these should be the XMPP field names, not the
 * ldap field names (as defined in ldap.searchFields)</dt>
 * </dl>
 */
public class ExtendedLdapUserProvider implements UserProvider
{
    private static final Logger Log = LoggerFactory
            .getLogger(LdapUserProvider.class);

    // LDAP date format parser.
    private static String LDAP_DATE_FORMAT_STRING = "yyyyMMddHHmmss";

    /**
     * This is the ldap user provider which will be used to delegate calls to.
     */
    private final LdapUserProvider delegate;

    /**
     * The {@link LdapManager} instance to use for LDAP access.
     */
    private final LdapManager manager;

    /**
     * The XMPPServer instance to use.
     */
    private final XMPPServer xmppServer;

    /**
     * A template to use for the user's xmpp display (nick) name. Replacements
     * can be made by enclosing ldap attributes names in curly braces.<br />
     * For example: "{familyName} {sn}"
     */
    private String displayNameTemplate;

    /**
     * This is an array of fieldnames, the union of the usual fields and those
     * extracted from the {@link #displayNameTemplate}. This is used to limit
     * the fields retrieved from ldap to only those actually required.
     */
    private String[] userAttributesToLoad;

    /**
     * If this property is set to true, then search string will be split into
     * separate search terms
     */
    private boolean seperateSearchTerms;

    /**
     * We have to replicate the searchFields logic here because we don't have
     * enough access to the delegate
     */
    private Map<String, String> searchFields;

    /**
     * The set of fields which will be searched through if a query for "Name" is
     * received
     */
    private Set<String> searchNameFields;

    /**
     * Default constructor which will configure all the dependencies from
     * openfire properties.
     */
    public ExtendedLdapUserProvider()
    {
        delegate = new LdapUserProvider();
        manager = LdapManager.getInstance();
        xmppServer = XMPPServer.getInstance();

        // Convert XML based provider setup to Database based
        JiveGlobals.migrateProperty("ldap.displayNameTemplate");
        JiveGlobals.migrateProperty("ldap.seperateSearchTerms");
        JiveGlobals.migrateProperty("ldap.searchFields");
        JiveGlobals.migrateProperty("ldap.searchNameFields");

        seperateSearchTerms = false;
        String seperateSearchTermsStr = JiveGlobals
                .getProperty("ldap.seperateSearchTerms");
        if (seperateSearchTermsStr != null) {
            seperateSearchTerms = Boolean.valueOf(seperateSearchTermsStr);
        }

        searchFields = parseSearchFields(JiveGlobals
                .getProperty("ldap.searchFields"));

        searchNameFields = parseSearchNameFields(JiveGlobals
                .getProperty("ldap.searchNameFields"));

        setDisplayNameTemplate(JiveGlobals
                .getProperty("ldap.displayNameTemplate"));
    }

    /**
     * Constructor for testing into which all the dependencies can be passed.
     * 
     * @param ldapManager
     * @param delegate
     * @param xmppServer
     * @param displayNameTemplate
     * @param seperateSearchTerms
     * @param searchFieldString
     */
    ExtendedLdapUserProvider(final LdapManager ldapManager,
            final LdapUserProvider delegate, final XMPPServer xmppServer,
            final String displayNameTemplate,
            final boolean seperateSearchTerms, final String searchFieldsString,
            final String searchNameFieldsString)
    {
        this.manager = ldapManager;
        this.delegate = delegate;
        this.xmppServer = xmppServer;
        this.seperateSearchTerms = seperateSearchTerms;
        this.searchFields = parseSearchFields(searchFieldsString);
        this.searchNameFields = parseSearchNameFields(searchNameFieldsString);

        setDisplayNameTemplate(displayNameTemplate);
    }

    public User loadUser(String username) throws UserNotFoundException
    {
        if (username.contains("@")) {
            if (!xmppServer.isLocal(new JID(username))) {
                throw new UserNotFoundException(
                        "Cannot load user of remote server: " + username);
            }
            username = username.substring(0, username.lastIndexOf("@"));
        }
        // Un-escape username.
        username = JID.unescapeNode(username);
        DirContext ctx = null;
        try {
            String userDN = manager.findUserDN(username);
            ctx = manager.getContext(manager.getUsersBaseDN(username));

            Attributes attrs = ctx.getAttributes(userDN, userAttributesToLoad);

            String name = constructDisplayName(attrs);

            if (Log.isDebugEnabled()) {
                Log.debug("Using " + name + " as display name for user "
                        + username);
            }

            String email = null;
            Attribute emailField = attrs.get(manager.getEmailField());
            if (emailField != null) {
                email = (String) emailField.get();
            }

            Date creationDate = new Date();
            Attribute creationDateField = attrs.get("createTimestamp");
            if (creationDateField != null
                    && "".equals(((String) creationDateField.get()).trim())) {
                creationDate = parseLDAPDate((String) creationDateField.get());
            }

            Date modificationDate = new Date();
            Attribute modificationDateField = attrs.get("modifyTimestamp");
            if (modificationDateField != null
                    && "".equals(((String) modificationDateField.get()).trim())) {
                modificationDate = parseLDAPDate((String) modificationDateField
                        .get());
            }

            // Escape the username so that it can be used as a JID.
            username = JID.escapeNode(username);
            return new User(username, name, email, creationDate,
                    modificationDate);
        } catch (Exception e) {
            throw new UserNotFoundException(e);
        } finally {
            try {
                if (ctx != null) {
                    ctx.close();
                }
            } catch (Exception ignored) {
                // Ignore.
            }
        }
    }

    /**
     * Sets the template used to construct the user's display name.
     * 
     * @param displayNameTemplate
     */
    public void setDisplayNameTemplate(final String displayNameTemplate)
    {
        this.displayNameTemplate = displayNameTemplate;

        final Set<String> fields = new HashSet<String>();

        fields.add(manager.getUsernameField());
        fields.add(manager.getNameField());
        fields.add(manager.getEmailField());
        fields.add("createTimestamp");
        fields.add("modifyTimestamp");

        if (displayNameTemplate != null) {
            Pattern pattern = Pattern.compile("\\{([^\\}]+)\\}");

            Matcher matcher = pattern.matcher(displayNameTemplate);

            while (matcher.find()) {
                fields.add(matcher.group(1));
            }
        }

        userAttributesToLoad = new String[fields.size()];

        userAttributesToLoad = fields.toArray(userAttributesToLoad);
    }

    public User createUser(String username, String password, String name,
            String email) throws UserAlreadyExistsException
    {
        return delegate.createUser(username, password, name, email);
    }

    public void deleteUser(String username)
    {
        delegate.deleteUser(username);
    }

    public int getUserCount()
    {
        return delegate.getUserCount();
    }

    public Collection<User> getUsers()
    {
        return delegate.getUsers();
    }

    public Collection<String> getUsernames()
    {
        return delegate.getUsernames();
    }

    public Collection<User> getUsers(int startIndex, int numResults)
    {
        return delegate.getUsers(startIndex, numResults);
    }

    public void setName(String username, String name)
            throws UserNotFoundException
    {
        delegate.setName(username, name);
    }

    public void setEmail(String username, String email)
            throws UserNotFoundException
    {
        delegate.setEmail(username, email);
    }

    public void setCreationDate(String username, Date creationDate)
            throws UserNotFoundException
    {
        delegate.setCreationDate(username, creationDate);
    }

    public void setModificationDate(String username, Date modificationDate)
            throws UserNotFoundException
    {
        delegate.setModificationDate(username, modificationDate);
    }

    public Set<String> getSearchFields() throws UnsupportedOperationException
    {
        return delegate.getSearchFields();
    }

    public Collection<User> findUsers(Set<String> fields, String query)
            throws UnsupportedOperationException
    {
        return this.findUsers(fields, query, -1, -1);
    }

    public Collection<User> findUsers(Set<String> fields, String query,
            int startIndex, int numResults)
            throws UnsupportedOperationException
    {
        if (Log.isDebugEnabled()) {
            Log.debug(this.getClass().getSimpleName() + ": Search for " + query);
            Log.debug(this.getClass().getSimpleName() + ": Fields "
                    + fields.toString());
        }

        if (fields.isEmpty() || query == null || "".equals(query)) {
            return Collections.emptyList();
        }
        if (!searchFields.keySet().containsAll(fields)) {
            throw new IllegalArgumentException("Search fields " + fields
                    + " are not valid.");
        }

        Set<String> fieldsToSearch = new HashSet<String>(fields);

        if (fieldsToSearch.contains("Name")) {
            fieldsToSearch.remove("Name");
            fieldsToSearch.addAll(searchNameFields);
        }

        String[] searchTerms;

        if (seperateSearchTerms) {
            // Split the query into search terms
            searchTerms = query.split("\\s+");
        } else {
            searchTerms = new String[] { query };
        }

        StringBuilder filter = new StringBuilder();
        // Add the global search filter so only those users the directory
        // administrator wants to include
        // are returned from the directory
        filter.append("(&(");
        filter.append(MessageFormat.format(manager.getSearchFilter(), "*"));
        filter.append(")");
        for (String searchTerm : searchTerms) {
            searchTerm = processSearchTerm(searchTerm);

            if (fieldsToSearch.size() > 1) {
                filter.append("(|");
            }
            for (String field : fieldsToSearch) {
                String attribute = searchFields.get(field);
                filter.append("(").append(attribute).append("=")
                        .append(searchTerm).append(")");
            }
            if (fieldsToSearch.size() > 1) {
                filter.append(")");
            }
        }
        filter.append(")");
        if (Log.isDebugEnabled()) {
            Log.debug(this.getClass().getSimpleName() + ": ldap query = "
                    + filter.toString());
        }

        List<String> userlist = manager.retrieveList(
                manager.getUsernameField(), filter.toString(), startIndex,
                numResults, manager.getUsernameSuffix());
        return new UserCollection(userlist.toArray(new String[userlist.size()]));
    }

    public boolean isReadOnly()
    {
        return delegate.isReadOnly();
    }

    public boolean isNameRequired()
    {
        return delegate.isNameRequired();
    }

    public boolean isEmailRequired()
    {
        return delegate.isEmailRequired();
    }

    /**
     * Parses dates/time stamps stored in LDAP. Some possible values:
     * 
     * <ul>
     * <li>20020228150820</li>
     * <li>20030228150820Z</li>
     * <li>20050228150820.12</li>
     * <li>20060711011740.0Z</li>
     * </ul>
     * 
     * @param dateText
     *            the date string.
     * @return the Date.
     */
    private static Date parseLDAPDate(String dateText)
    {
        // If the date ends with a "Z", that means that it's in the UTC time
        // zone. Otherwise,
        // Use the default time zone.
        boolean useUTC = false;
        if (dateText.endsWith("Z")) {
            useUTC = true;
        }
        Date date = new Date();
        try {
        	final SimpleDateFormat ldapDateFormat = new SimpleDateFormat(
                    LDAP_DATE_FORMAT_STRING);
            if (useUTC) {
                ldapDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
            } else {
                ldapDateFormat.setTimeZone(TimeZone.getDefault());
            }
            date = ldapDateFormat.parse(dateText);
        } catch (Exception e) {
            Log.error(e.getMessage(), e);
        }
        return date;
    }

    /**
     * Parses the string parameter for the search fields into a map
     */
    private Map<String, String> parseSearchFields(final String searchFields)
    {
        final Map<String, String> searchFieldMap = new LinkedHashMap<String, String>();

        if (searchFields == null) {
            searchFieldMap.put("Username", manager.getUsernameField());
            searchFieldMap.put("Name", manager.getNameField());
            searchFieldMap.put("Email", manager.getEmailField());
        } else {
            try {
                for (StringTokenizer i = new StringTokenizer(searchFields, ","); i
                        .hasMoreTokens();) {
                    String[] field = i.nextToken().split("/");
                    searchFieldMap.put(field[0], field[1]);
                }
            } catch (Exception e) {
                Log.error("Error parsing LDAP search fields: " + searchFields,
                        e);
            }
        }

        return searchFieldMap;
    }

    /**
     * Parses the string parameter for the search name fields into a set.
     */
    private Set<String> parseSearchNameFields(
            final String searchNameFieldsString)
    {
        if (searchNameFieldsString == null) {
            return null;
        }

        final Set<String> searchNameFields = new HashSet<String>();

        String[] fields = searchNameFieldsString.split(",");

        for (String field : fields) {
            searchNameFields.add(field.trim());
        }

        return searchNameFields;
    }

    /**
     * Adds wilcarding onto a search string and replaces naughty ldap characters
     */
    private String processSearchTerm(final String term)
    {
        String result;

        result = term.replace("\\", "\\5c").replace("(", "\\28")
                .replace(")", "\\29").replace("/", "\\2f");

        if (!result.endsWith("*")) {
            result = result + "*";
        }

        return (result);
    }

    /**
     * Replaces the various bits of data into the display name template string.
     * 
     * @param attrs
     *            the attributes for the user.
     * @return the display name.
     * @throws NamingException
     */
    private String constructDisplayName(final Attributes attrs)
            throws NamingException
    {
        if (displayNameTemplate == null) {
            Attribute attr = attrs.get(manager.getNameField());

            if (attr != null) {
                return (String) attr.get();
            }

            return null;
        }

        Pattern pattern = Pattern.compile("\\{([^\\}]+)\\}");

        Matcher matcher = pattern.matcher(displayNameTemplate);

        StringBuffer result = new StringBuffer();

        while (matcher.find()) {
            Attribute attr = attrs.get(matcher.group(1));

            if (attr != null) {
                matcher.appendReplacement(result, (String) attr.get());
            } else {
                matcher.appendReplacement(result, "");
            }
        }

        matcher.appendTail(result);

        return result.toString().trim();
    }
}
