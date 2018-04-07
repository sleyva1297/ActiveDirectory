using ActiveDirectory.Classes;
using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Script.Serialization;

namespace ActiveDirectory.Controllers
{
    public class ActiveDirectoryController : Controller
    {
        // GET: ActiveDirectory
        public ActionResult Index()
        {
            return View();
        }

        //Retrieves Current Authenticated User
        public JsonResult WhoAmI()
        {
            return Json(Authorize.GetCurrentAuthUser(),JsonRequestBehavior.AllowGet);
        }

        //Verifies if current user is in Active Directory Group
        //Client Side
        [HttpPost]
        public bool inGroup(string group)
        {
            return Authorize.InGroup(group);
        }

        //Get AD Groups - client side
        public JsonResult GetAdGroups()
        {
            return Json(AD.ADGroups(), JsonRequestBehavior.AllowGet);
        }

        //Returns to client whether is admin
        public bool isAdmin()
        {
            return Authorize.IsAdmin();
        }

        //Get all locked users 
        public JsonResult GetLockedUsers()
        {
            //Returns a list of all locked users if user is admin or IT
            if (Authorize.InGroup(Authorize.IT))
            {
                return Json(AD.LockedUsersToList(), JsonRequestBehavior.AllowGet);
            }

            return null;
        }

        //Unlock Users
        [HttpPost]
        public JsonResult UnlockUser(string UserName)
        {

            if (Authorize.InGroup(Authorize.IT))
            {
                PrincipalContext Context = new PrincipalContext(ContextType.Domain, "YOURDOMAIN", "username", "password");
                UserPrincipal user = UserPrincipal.FindByIdentity(Context, IdentityType.SamAccountName, UserName);
                bool isLocked = user.IsAccountLockedOut();
                if (isLocked)
                {
                    user.UnlockAccount();
                    isLocked = false;
                }

                return Json(AD.LockedUsersToList(), JsonRequestBehavior.AllowGet);
            }
            return null;
        }

        //Unlock and reset user to generic password
        [HttpPost]
        public JsonResult ResetPassword(string UserName)
        {
            if (Authorize.InGroup(Authorize.IT))
            {
                PrincipalContext Context = new PrincipalContext(ContextType.Domain, "YOURDOMAIN", "username", "password");
                UserPrincipal user = UserPrincipal.FindByIdentity(Context, IdentityType.SamAccountName, UserName);

                user.SetPassword("password"); //Not the best idea to hardcode this
                user.ExpirePasswordNow();
                bool isLocked = user.IsAccountLockedOut();
                if (isLocked)
                {
                    user.UnlockAccount();
                }

                return Json(AD.LockedUsersToList(), JsonRequestBehavior.AllowGet);
            }

            return null;
        }

        //Network permitted logon hours

        //Classes
        //Active Directory Hours Class
        class ADHours
        {
            public BitArray binary { get; set; }
            public string user { get; set; }
            public byte[] hours { get; set; }
            public bool isSuccessful { get; set; }
        }

        //User Class
        class user
        {
            public string FirstName { get; set; }
            public string LastName { get; set; }
            public string username { get; set; }
        }

        //Returns a list of usernames to the frontend for predictive text
        public JsonResult GetUsernames()
        {
            //Returns if user is an Admin or in specified IT Active Directory Group
            if (Authorize.InGroup(Authorize.IT))
            {
                List<user> users = new List<user>();
                PrincipalContext ctx = new PrincipalContext(ContextType.Domain, "YOURDOMAIN"); //Sets the context for the operation
                PrincipalSearcher searcher = new PrincipalSearcher(new UserPrincipal(ctx));
                UserPrincipal principal = new UserPrincipal(ctx);
                principal.Enabled = true;
                searcher.QueryFilter = principal;
                foreach (var item in searcher.FindAll())
                {
                    user user = new user();
                    user.username = item.SamAccountName;
                    var name = item.DisplayName.Split(' ');
                    user.FirstName = name[0].Trim();
                    user.LastName = name[1].Trim();
                    users.Add(user);
                }
                return Json(users, JsonRequestBehavior.AllowGet);
            }
            return null;
        }

        //Returns Current Network hours to the frontend
        public JsonResult GetNetworkHours(string userName)
        {

            if (Authorize.InGroup(Authorize.IT))
            {
                /*************************
                * GMT-7
                * Set Start and Stop Time
                * Sunday binary[7]-binary[30]
                * Monday binary[31]-binary[54]
                * Tuesday binary[55]-binary[78]
                * Wednesday binary[79]-binary[102]
                * Thursday binary[103]-binary[126]
                * Friday binary[127]-binary[150]
                * Saturday binary[151]-binary[6]
                *************************/

                //Creates the Return value object
                ADHours ADHours = new ADHours();

                //Grabs the actual hours out of Active Directory
                if (!userName.Contains("Admin"))
                {
                    byte[] hours = AD.GetLogOnHours(userName);

                    //Converts to BitArray
                    BitArray setHours = new BitArray(hours);

                    //Sets Our return objects values and returns object to client
                    ADHours.binary = setHours;
                    ADHours.user = userName;
                    ADHours.hours = hours;

                    return Json(ADHours, JsonRequestBehavior.AllowGet);
                }
                else
                {
                    return Json("Admins are not controlled with this function", JsonRequestBehavior.AllowGet);
                }
            }

            return null;

        }

        //JSON should be posted as a bool array 
        [HttpPost]
        public void SubmitRequest(string user, string json)
        {
            if (Authorize.InGroup(Authorize.IT))
            {
                ADHours result = new ADHours();
                byte[] ADHours;
                JavaScriptSerializer js = new JavaScriptSerializer();
                bool[] ADhoursBools = js.Deserialize<bool[]>(json);
                BitArray ADHoursBits = new BitArray(ADhoursBools);
                ADHours = ToByteArray(ADHoursBits);

                result.binary = ADHoursBits;
                result.hours = ADHours;
                result.user = user;

                AD.SetLogonHours(user, ADHours);
            }
        }

        //Returns my bitarray to a Byte Array to be input into Active Directory
        private byte[] ToByteArray(BitArray bits)
        {
            byte[] bytes = new byte[21];
            bits.CopyTo(bytes, 0);
            return bytes;
        }
    }
}
