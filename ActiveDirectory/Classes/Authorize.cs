using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ActiveDirectory.Classes
{
    public class Authorize
    {

        /*****************************************************
         *  Authorize Class provides authentication services
         *  to the intranet site.
         * **************************************************/

        //Active Directory Groups
        //Customizable
        protected internal static string Admins = "Intranet Admin Group";
        protected internal static string Editors = "Intranet Editor";
        protected internal static string IT = "Intranet-IT";
        protected internal static string HR = "Intranet-HR";
        protected internal static string Loans = "Intranet-Loans";
        protected internal static string Operations = "Intranet-Operations";

        //Evaluates if the current windows user is a webmaster
        private static bool Webmaster()
        {
            string user = GetCurrentAuthUser();

            //This gives the web master or lead developer(or list of developers) complete access to all features of Intranet Site for testing and debug purposes
            //Customizable 
            string[] webmaster = { "regular user" };
            string[] webmasterAdmin = { "domain_Admin" };

            bool rval = false;

            if (webmaster.Contains(user.ToLower()) || webmasterAdmin.Contains(user.ToLower()))
            {
                rval = true;
            }
            return rval;
        }

        //Requests current authenticated user from IIS
        protected internal static string GetCurrentAuthUser()
        {
            string name = HttpContext.Current.Request.ServerVariables["AUTH_USER"].Replace("YOURDOMAIN\\", "").ToLower();
            return name;
        }

        //Checks if user is an admin
        protected internal static bool IsAdmin()
        {
            bool returnValue = false;

            if (Webmaster())
            {
                returnValue = true;
            }

            if (InGroup(Admins))
            {
                returnValue = true;
            }

            else if (InGroup(Editors))
            {
                returnValue = true;
            }

            return returnValue;
        }

        //Server side
        protected internal static bool InGroup(string group)
        {
            List<string> groups = AD.ADGroups();

            if (groups.Contains(group))
            {
                return true;
            }

            if (Webmaster())
            {
                return true;
            }

            else
            {
                return false;
            }
        }

    }
}