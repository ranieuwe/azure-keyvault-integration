using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace KVWA.MVCtoSQLDB.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        /// <summary>
        /// Simple dirty method to retrieve some columns and rows from a SQL DB and dump them on the screen
        /// The authentication used is AccessToken, AAD
        /// </summary>
        /// <returns></returns>
        public async Task<ActionResult> SQLDB()
        {
            try
            {
                var connectionString = ConfigurationManager.ConnectionStrings["sqlexample"];
                using (SqlConnection connection = new SqlConnection(connectionString.ToString()))
                {
                    SqlDataAdapter adapter = new SqlDataAdapter("SELECT TOP (10) * FROM [SalesLT].[Product]", connection);
                    DataTable dt = new DataTable();
                    // Load the accesstoken into the connection string so that those credentials are used
                    connection.AccessToken = await GetAccessToken();
                    adapter.Fill(dt);
                    ViewBag.Message = "Succesfully requested a query from SQL DB. Total rows: " + dt.Rows.Count;
                    return View(dt);
                }
            }
            catch(Exception e)
            {
                System.Diagnostics.Trace.TraceError(e.ToString());
                ViewBag.Message = e.ToString();
                return View();
            }
        }

        public static async Task<string> GetAccessToken()
        {
            // Some essential settings we need
            string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
            string CertCN = ConfigurationManager.AppSettings["ida:CertCN"];
            
            // Initialize the Certificate Credential to be used by ADAL.
            // First find the matching certificate in the cert store.
            X509Certificate2 cert = null;

            // Store on the app service the cert is loaded into as well on localhost is current user, not local machine, machine is shared!
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                // Place all certificates in an X509Certificate2Collection object.
                X509Certificate2Collection certCollection = store.Certificates;
                // Find unexpired certificates.
                X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                // From the collection of unexpired certificates, find the ones with the correct name, this is the CN we provided during creation in KV
                X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySubjectName, CertCN, false);
                if (signingCert.Count == 0)
                {
                    throw new Exception("Cannot find certificate: " + CertCN);
                }
                // Return the first certificate in the collection, has the right name and is current.
                cert = signingCert[0];
            }
            finally
            {
                store.Close();
            }

            // Then create the certificate credential, this means we say we are the given user for impersonation
            var certCred = new ClientAssertionCertificate(clientId, cert);
            return await AcquireToken(certCred);
        }

        static async Task<string> AcquireToken(ClientAssertionCertificate certCred)
        {
            AuthenticationResult result = null;

            string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
            string tenant = ConfigurationManager.AppSettings["ida:Tenant"];

            string sqlDBResourceId = ConfigurationManager.AppSettings["sqldb:ResourceId"];

            string authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

            // Create context for the authority created and retrieve token
            var authContext = new AuthenticationContext(authority);

            // Get an access token from Azure AD using client credentials.
            result = await authContext.AcquireTokenAsync(sqlDBResourceId, certCred);

            return result.AccessToken;
        }
    }
}