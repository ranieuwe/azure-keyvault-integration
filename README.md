# KVWA

## What is this?
Some code and PowerShell scripts to make KeyVault interact with WebApp and have WebApp cert to SQL DB using certificate/AAD authentication.

The beauty of this solution is that it is completely passwordless for the developer. They'll never see any connection details to the database allowing the system administrator to shield the database and its credentials. 

A side benefit is that certificate rotation is very easy to do.

## How to build the C# app

1. Make a new solution (e.g. MVC5)
2. The .NET framework MUST be set to 4.6.1. Prior versions do not support access tokens on the SQL Connection string
3. Set the following configuration keys on the web.config
    * `ida:Tenant`: this is the tenant we work in, e.g. at Microsoft this microsoft.onmicrosoft.com 
    * `ida:ClientId`: this is the service principal we are operating as
    * `ida:CertCN`: this is the identifier for the certificate (common name)
    * `connectionString`: the connectionstring to the database. Along the lines of `Data Source=sqlserver.database.windows.net; Initial Catalog=database`
4. First install ADAL by executing `Install-Package Microsoft.IdentityModel.Clients.ActiveDirectory` in the package manager console
5. Set up some logic to obtain an access token. Here is an example:

```csharp
public static async Task<string> GetAccessToken()
{

    string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
    string CertCN = ConfigurationManager.AppSettings["ida:CertCN"];
    
    // Initialize the Certificate Credential to be used by ADAL.
    // First find the matching certificate in the cert store.
    X509Certificate2 cert = null;
    X509Store store = new X509Store(StoreLocation.CurrentUser);
    try
    {
        store.Open(OpenFlags.ReadOnly);
        // Place all certificates in an X509Certificate2Collection object.
        X509Certificate2Collection certCollection = store.Certificates;
        // Find unexpired certificates.
        X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
        // From the collection of unexpired certificates, find the ones with the correct name.
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

    // Then create the certificate credential.
    var certCred = new ClientAssertionCertificate(clientId, cert);
    return await AcquireToken(certCred);
}

static async Task<string> AcquireToken(ClientAssertionCertificate certCred)
{
    // Get an access token from Azure AD using client credentials.
    // If the attempt to get a token fails because the server is unavailable, retry twice after 3 seconds each.
    AuthenticationResult result = null;
    int retryCount = 0;
    bool retry = false;

    string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
    string tenant = ConfigurationManager.AppSettings["ida:Tenant"];

    string sqlDBResourceId = ConfigurationManager.AppSettings["sqldb:ResourceId"];

    string authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

    var authContext = new AuthenticationContext(authority);
    result = await authContext.AcquireTokenAsync(sqlDBResourceId, certCred);

    return result.AccessToken;
}
```
6. Set up a request to SQL DB and pass the token into the connection like so:

```csharp
var connectionString = ConfigurationManager.ConnectionStrings["DefaultConnection"];
using (SqlConnection connection = new SqlConnection(connectionString.ToString()))
{
    SqlDataAdapter adapter = new SqlDataAdapter("SELECT TOP (10) * FROM [SalesLT].[Product]", connection);
    DataTable dt = new DataTable();
    connection.AccessToken = await GetAccessToken();
    adapter.Fill(dt);
}
```