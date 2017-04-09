using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

namespace ActiveDirectory.Classes
{
    public class AD
    {

        //Used to store neccessary items from Active Directory
        public class Users
        {
            public string Email { get; set; }
            public string UserName { get; set; }
            public string DisplayName { get; set; }
        }

        //Retrives Logon hours from Active Directory
        protected internal static byte[] GetLogOnHours(string userName)
        {
            //Returns if user is an Admin or in specified IT Active Directory Group
            if (Authorize.InGroup(Authorize.IT))
            {
                PrincipalContext ctx = new PrincipalContext(ContextType.Domain, "YOURDOMAIN"); //Sets the context for the operation
                UserPrincipal u = UserPrincipal.FindByIdentity(ctx, userName); //Finds the user based on username
                var logonHours = u.PermittedLogonTimes; //Returns hours in byte array format
                return logonHours;
            }

            //If not returns null
            return null;
        }

        //Sets log in users
        protected internal static void SetLogonHours(string userName, byte[] hours)
        {
            if (Authorize.InGroup(Authorize.IT))
            {
                PrincipalContext Context = new PrincipalContext(ContextType.Domain, "YOURDOMAIN", "username", "password");
                UserPrincipal u = UserPrincipal.FindByIdentity(Context, userName);
                u.PermittedLogonTimes = hours;
                u.Save();
            }
        }

        //Returns all locked user to list
        protected internal static List<string> LockedUsersToList()
        {
            //List that will contain locked users
            List<string> lstADUsers = new List<string>();

            //Directory
            DirectoryEntry Domain = new DirectoryEntry("LDAP://DC=YOURDOMAIN,DC=DOM");

            //Directory Searcher
            DirectorySearcher search = new DirectorySearcher(Domain);

            //Properties we want 
            search.PropertiesToLoad.Add("samaccountname"); //Username
            search.PropertiesToLoad.Add("displayname"); //first name
            search.Filter = String.Format("(&(objectCategory=Person)(objectClass=User)(lockoutTime>=1)(!givenName=Guest))"); //GetLockedUsers

            //Initializes Search result to hold info
            SearchResult result;

            //Returns all usres to array of search results
            var res = search.FindAll();

            if (res != null) //If there are locked out users
            {
                for (int counter = 0; counter < res.Count; counter++)
                {
                    string username = string.Empty;
                    result = res[counter];
                    if (result.Properties.Contains("samaccountname") && result.Properties.Contains("displayname"))
                    {
                        Users user = new Users();
                        user.UserName = (String)result.Properties["samaccountname"][0];
                        user.DisplayName = (String)result.Properties["displayname"][0];
                        lstADUsers.Add(user.UserName);
                    }
                }
            }
            //Clean up
            Domain.Dispose();
            search.Dispose();
            res.Dispose();

            //Return
            return lstADUsers;

        }

        //Return Active Directory Groups to list string
        protected internal static List<string> ADGroups()
        {
            string user = Authorize.GetCurrentAuthUser();

            DirectoryEntry obEntry = new DirectoryEntry("LDAP://DC=YOURDOMAIN,DC=YOURDOMAIN");

            List<string> groups = new List<string>();

            DirectorySearcher search = new DirectorySearcher(obEntry);
            search.Filter = String.Format("(anr={0})", user);

            SearchResult res = search.FindOne();
            if (null != res)
            {
                DirectoryEntry obUser = new DirectoryEntry(res.Path);
                // Invoke Groups method.
                object obGroups = obUser.Invoke("Groups");
                foreach (object ob in (IEnumerable)obGroups)
                {
                    // Create object for each group.
                    DirectoryEntry obGpEntry = new DirectoryEntry(ob);
                    groups.Add(obGpEntry.Name.Replace("CN=", ""));
                }

            }

            else
            {
                groups.Add("Error");
            }

            return groups;
        }

    }
}