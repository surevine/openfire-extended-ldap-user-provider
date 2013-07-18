package com.surevine.chat.openfire.ldap;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapContext;

import org.apache.commons.collections.CollectionUtils;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.ldap.LdapManager;
import org.jivesoftware.openfire.ldap.LdapUserProvider;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest(UserManager.class)
public class ExtendedLdapUserProviderTest
{

    final String TEST_DISPLAY_NAME_TEMPLATE = "{givenName} {sn}";
    final String TEST_SEARCH_FIELDS = "Username/uid,Name/uid,Email/mail,Given Name/givenName,Family Name/sn";
    final String TEST_SEARCH_NAME_FIELDS = "Given Name,Family Name";

    /**
     * The class under test.
     */
    ExtendedLdapUserProvider userProvider;

    /**
     * The (mocked) LdapManager.
     */
    @Mock
    LdapManager manager;

    /**
     * The (mocked) LdapUserProvider delegate.
     */
    @Mock
    LdapUserProvider delegate;

    @Mock
    UserManager userManager;

    @Mock
    XMPPServer xmppServer;

    /**
     * Some mocked ldap attributes which returns the fieldname when asked for a
     * field value.
     */
    @Mock
    Attributes attrs;

    final Map<String, String> attributeOverrides = new HashMap<String, String>();

    @Before
    public void setUp() throws Exception
    {
        MockitoAnnotations.initMocks(this);

        when(attrs.get(anyString())).thenAnswer(new Answer<Attribute>() {
            public Attribute answer(InvocationOnMock invocation)
                    throws Throwable
            {
                // If the key exists in attributeOverrides then return the value
                // from that, otherwise return the key
                String retVal;

                if (attributeOverrides.containsKey(invocation.getArguments()[0])) {
                    retVal = attributeOverrides.get(invocation.getArguments()[0]);
                } else {
                    retVal = (String) invocation.getArguments()[0];
                }

                if (retVal == null) {
                    return null;
                }

                Attribute attr = mock(Attribute.class);

                when(attr.get()).thenReturn(retVal);

                return attr;
            }
        });

        userProvider = new ExtendedLdapUserProvider(manager, delegate,
                xmppServer, TEST_DISPLAY_NAME_TEMPLATE, true,
                TEST_SEARCH_FIELDS, TEST_SEARCH_NAME_FIELDS);

        PowerMockito.mockStatic(UserManager.class);

        when(UserManager.getInstance()).thenReturn(userManager);
        when(UserManager.getUserProvider()).thenReturn(userProvider);

        when(manager.getNameField()).thenReturn("sn");
        when(manager.getUsernameField()).thenReturn("uid");

    }

    @After
    public void tearDown() throws Exception
    {
    }

    @Test
    public void testLoadUser() throws Exception
    {
        String username = "testuser";

        User user = loadUser(username, attrs);

        assertEquals("Name not correctly set", "givenName sn", user.getName());
    }

    @Test
    public void testLoadUserWithNoGivenName() throws Exception
    {
        String username = "testuser";

        attributeOverrides.put("givenName", null);

        User user = loadUser(username, attrs);

        assertEquals("Name not correctly set", "sn", user.getName());
    }

    @Test
    public void testLoadUserWithNoNameTemplate() throws Exception
    {
        String username = "testuser";

        userProvider = new ExtendedLdapUserProvider(manager, delegate,
                xmppServer, null, true, TEST_SEARCH_FIELDS,
                TEST_SEARCH_NAME_FIELDS);

        User user = loadUser(username, attrs);

        assertEquals("Name not correctly set", "sn", user.getName());
    }

    @Test
    public void testFindUsersSingleTermWithNaughtyCharacters()
            throws UserNotFoundException
    {
        String searchTerm = "*sea()\\/rch*";
        String escapedSearchTerm = "*sea\\28\\29\\5c\\2frch*";

        when(manager.getSearchFilter()).thenReturn("(uid={0})");

        Set<String> testFields = new HashSet<String>();
        testFields.add("Name");

        // We're expecting the name search to be expanded to cover givenName and
        // sn.
        String expected = "(&((uid=*))(|(sn=" + escapedSearchTerm
                + ")(givenName=" + escapedSearchTerm + ")))";

        testFindUsers(searchTerm, expected, testFields, -1, -1);
    }

    @Test
    public void testFindUsersSingleTerm() throws UserNotFoundException
    {
        String searchTerm = "*search*";

        // We're expecting the name search to be expanded to cover givenName and
        // sn.
        String expected = "(&((uid=*))(|(sn=" + searchTerm + ")(givenName="
                + searchTerm + ")))";

        Set<String> testFields = new HashSet<String>();
        testFields.add("Name");

        testFindUsers(searchTerm, expected, testFields, -1, -1);
    }

    @Test
    public void testFindUsersMultipleTerms() throws UserNotFoundException
    {
        String term1 = "*search*";
        String term2 = "*term*";
        String searchTerm = term1 + " " + term2;

        // We're expecting the terms to be split out and the name search to be
        // expanded to cover givenName and sn.
        String expected = "(&((uid=*))(|(sn=" + term1 + ")(givenName=" + term1
                + "))(|(sn=" + term2 + ")(givenName=" + term2 + ")))";

        Set<String> testFields = new HashSet<String>();
        testFields.add("Name");

        testFindUsers(searchTerm, expected, testFields, -1, -1);
    }

    @Test
    public void testFindUsersSingleTermNotSeparated() throws UserNotFoundException
    {
        String searchTerm = "*search term*";
        
        userProvider = new ExtendedLdapUserProvider(manager, delegate,
                xmppServer, TEST_DISPLAY_NAME_TEMPLATE, false,
                TEST_SEARCH_FIELDS, TEST_SEARCH_NAME_FIELDS);
        
        // We're expecting the name search to be expanded to cover givenName and
        // sn.
        String expected = "(&((uid=*))(|(sn=" + searchTerm + ")(givenName="
                + searchTerm + ")))";

        Set<String> testFields = new HashSet<String>();
        testFields.add("Name");

        testFindUsers(searchTerm, expected, testFields, -1, -1);
    }
    private User loadUser(String username, Attributes attrs) throws Exception
    {
        String userDn = "cn=" + username + ",ou=test";
        String userBaseDn = "ou=test";
        LdapContext context = mock(LdapContext.class);

        when(manager.findUserDN(username)).thenReturn(userDn);
        when(manager.getUsersBaseDN(username)).thenReturn(userBaseDn);
        when(manager.getContext(userBaseDn)).thenReturn(context);
        when(context.getAttributes(anyString(), any(String[].class)))
                .thenReturn(attrs);
        when(context.getAttributes(anyString())).thenReturn(attrs);

        return userProvider.loadUser(username);
    }

    private void testFindUsers(String search, String expectedQuery,
            Set<String> fields, int startIndex, int numResults)
            throws UserNotFoundException
    {
        when(manager.getSearchFilter()).thenReturn("(uid={0})");

        List<String> resultList = Arrays.asList("testuser1", "testuser2");

        // Only return something if the expected happens
        when(
                manager.retrieveList("uid", expectedQuery, startIndex,
                        numResults, null)).thenReturn(resultList);

        Collection<User> result = userProvider.findUsers(fields, search,
                startIndex, numResults);

        verify(manager).retrieveList("uid", expectedQuery, startIndex,
                numResults, null);
        
        Collection<User> users = new HashSet<User>();

        for (String username : resultList) {
            User user = mock(User.class);

            users.add(user);

            when(userManager.getUser(username)).thenReturn(user);
        }

        assertTrue(
                "Users not correctly returned: "
                        + CollectionUtils.disjunction(result, users),
                CollectionUtils.isEqualCollection(result, users));
    }
}
