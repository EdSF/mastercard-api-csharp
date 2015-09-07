using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;


namespace MasterCard.SDK
{
    /// <summary>
    /// This class defines the base functionality of the MasterCard API.
    /// </summary>
    public class Connector
    {

        private const long UNIX_EPOCH_TICKS = 621355968000000000L;

        public static string EMPTY_STRING = "";
        protected static string EQUALS = "=";
        protected static string AMP = "&";
        private static string QUESTION_MARK = "?";
        protected static string MESSAGE = "Message";
        protected static string HTTP_CODE = "HttpCode";
        protected static string COLON_2X_BACKSLASH = "://";
        protected static int SC_MULTIPLE_CHOICES = 300;
        protected static string REALM = "realm";
        protected static string OAUTH_CONSUMER_KEY = "oauth_consumer_key";
        protected static string OAUTH_VERSION = "oauth_version";
        protected static string OAUTH_SIGNATURE = "oauth_signature";
        protected static string OAUTH_SIGNATURE_METHOD = "oauth_signature_method";
        protected static string OAUTH_TIMESTAMP = "oauth_timestamp";
        protected static string OAUTH_NONCE = "oauth_nonce";
        protected static string OAUTH_BODY_HASH = "oauth_body_hash";
        private static string ONE_POINT_ZERO = "1.0";
        private static string RSA_SHA1 = "RSA-SHA1";
        private static string OAUTH_START_STRING = "OAuth ";
        private static string COMMA = ",";
        private static string DOUBLE_QOUTE = "\"";
        private static string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        private static readonly string[] UriRfc3986CharsToEscape = new[] { "!", "*", "'", "(", ")" };
        private const string HTML_TAG = "<html>";
        private const string BODY_OPENING_TAG = "<body>";
        private const string BODY_CLOSING_TAG = "</body>";

        private const string NULL_RESPONSE_PARAMETERS_ERROR = "ResponseParameters can not be null.";
        private const string NULL_PARAMETERS_ERROR = "Null parameters passed to method call";
        private const string NULL_PRIVATEKEY_ERROR_MESSAGE = "Private Key is null";

        private const string CONTENT_TYPE = "content-type";
        private const string CONTENT_LENGTH = "content-length";
        private const string APPLICATION_XML = "application/xml";
        private const string AUTHORIZATION = "Authorization";

        private static readonly Random random = new Random();
        private static readonly UTF8Encoding encoder = new UTF8Encoding();

        public string SignatureBaseString { get { return _signatureBaseString; } }
        public string AuthHeader { get { return _authHeader; } }
        private string ConsumerKey { get; set; }
        private AsymmetricAlgorithm privateKey { get; set; }
        private string _signatureBaseString;
        private string _authHeader;


        /// <summary>
        /// This constructor allows the caller to provide a preloaded private key for use 
        /// when OAuth calls are made.
        /// </summary>
        /// <param name="consumerKey"></param>
        /// <param name="privateKey"></param>
        public Connector(string consumerKey, AsymmetricAlgorithm privateKey)
        {
            ConsumerKey = consumerKey;
            this.privateKey = privateKey;

            // Turns the handling of a 100 HTTP server response ON
            ServicePointManager.Expect100Continue = true;
        }

        /// <summary> 
        /// This method will HTML encode all special characters in the string parameter
        /// </summary>
        /// <returns>The parameter string that was passed in with all special characters HTML encoded</returns>
        public string AllHtmlEncode(string value)
        {
            // call the normal HtmlEncode method first
            char[] chars = HttpUtility.HtmlEncode(value).ToCharArray();
            StringBuilder encodedValue = new StringBuilder();

            // Encode all the multi byte characters that the normal encoder misses
            foreach (char c in chars)
            {
                if ((int)c > 127) // above normal ASCII
                    encodedValue.Append("&#" + (int)c + ";");
                else
                    encodedValue.Append(c);
            }
            return encodedValue.ToString();
        }

        /******************** protected and support methods ***************************************************************************************************************************/
        protected virtual OAuthParameters OAuthParametersFactory()
        {
            OAuthParameters oparams = new OAuthParameters();
            oparams.addParameter(OAUTH_CONSUMER_KEY, ConsumerKey);
            oparams.addParameter(OAUTH_NONCE, getNonce());
            oparams.addParameter(OAUTH_TIMESTAMP, getTimestamp());
            oparams.addParameter(OAUTH_SIGNATURE_METHOD, RSA_SHA1);
            oparams.addParameter(OAUTH_VERSION, ONE_POINT_ZERO);
            return oparams;
        }

        /// <summary>
        /// This method receives a name value collection and returns the value of the 
        /// specified parameter.
        /// </summary>
        /// <param name="collection"></param>
        /// <param name="parameter"></param>
        /// <returns></returns>
        protected static string ParseResponseParameter(NameValueCollection collection, string parameter)
        {
            string value = (collection[parameter] ?? "").Trim();
            return (value.Length > 0) ? value : null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        /// <param name="requestMethod"></param>
        /// <param name="body"></param>
        /// <returns></returns>
        protected Dictionary<string, string> doRequest(string url, string requestMethod, string body)
        {
            return doRequest(url, requestMethod, OAuthParametersFactory(), body);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        /// <param name="requestMethod"></param>
        /// <returns></returns>
        protected Dictionary<string, string> doRequest(string url, string requestMethod)
        {
            return doRequest(url, requestMethod, OAuthParametersFactory(), null);
        }

        /// <summary>
        /// Method to handle all Api connection details.
        /// </summary>
        /// <param name="httpsURL"></param>
        /// <param name="requestMethod"></param>
        /// <param name="oparams"></param>
        /// <param name="body"></param>
        /// <returns></returns>
        protected Dictionary<string, string> doRequest(string httpsURL, string requestMethod, OAuthParameters oparams, string body)
        {
            try
            {
                if (privateKey == null)
                {
                    throw new MCApiRuntimeException(NULL_PRIVATEKEY_ERROR_MESSAGE);
                }
                if (!string.IsNullOrEmpty(body))
                {
                    oparams = setOauthBodyHashParameter(body, oparams);
                }

                HttpWebRequest con = setupConnection(httpsURL, requestMethod, oparams, body);

                if (body != null)
                {
                    writeBodyToConnection(body, con);
                }

                return checkForErrorsAndReturnRepsonse(con);
            }
            catch (Exception e)
            {
                throw new MCApiRuntimeException(e.Message, e);
            }
        }

        /* -------- private Methods ------------------------------------------------------------------------------------------------------------------ */

        /// <summary>
        /// Method to add the Oauth body hash to the OAuthParameters
        /// </summary>
        /// <param name="body"></param>
        /// <param name="oparams"></param>
        /// <returns></returns>
        private OAuthParameters setOauthBodyHashParameter(string body, OAuthParameters oparams)
        {
            byte[] bodyStringBytes = encoder.GetBytes(body);

            using (var sha = new SHA1CryptoServiceProvider())
            {
                try
                {
                    string encodedHash = Convert.ToBase64String(sha.ComputeHash(bodyStringBytes));
                    oparams.addParameter(OAUTH_BODY_HASH, encodedHash);
                    return oparams;
                }
                catch (CryptographicException cex)
                {
                    throw new MCApiRuntimeException(cex.Message, cex);
                }

            }

        }

        /// <summary>
        /// Setup the HttpWebRequest and connection headers
        /// </summary>
        /// <param name="httpsURL"></param>
        /// <param name="requestMethod"></param>
        /// <param name="oparams"></param>
        /// <param name="body"></param>
        /// <returns></returns>
        private HttpWebRequest setupConnection(string httpsURL, string requestMethod, OAuthParameters oparams, string body)
        {
            Uri url = new Uri(httpsURL);
            HttpWebRequest con = (HttpWebRequest)WebRequest.Create(url);
            con.Method = requestMethod;
            con.Headers.Add(AUTHORIZATION, buildAuthHeaderString(httpsURL, requestMethod, oparams));

            // Setting the Content Type header depending on the body
            if (body != null)
            {
                con.ContentType = APPLICATION_XML;
                con.ContentLength = body.Length;
            }
            return con;
        }

        /// <summary>
        /// Builds the Authorization header 
        /// </summary>
        /// <param name="httpsURL"></param>
        /// <param name="requestMethod"></param>
        /// <param name="oparams"></param>
        /// <returns></returns>
        private string buildAuthHeaderString(string httpsURL, string requestMethod, OAuthParameters oparams)
        {
            generateAndSignSignature(httpsURL, requestMethod, oparams);
            StringBuilder buffer = new StringBuilder();
            buffer.Append(OAUTH_START_STRING);
            buffer = parseParameters(buffer, oparams);
            _authHeader = buffer.ToString();
            return buffer.ToString();
        }

        /// <summary>
        /// Method to build a comma delimited list of key/value string for the signature base string and authorization header
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="oparams"></param>
        /// <returns></returns>
        private StringBuilder parseParameters(StringBuilder buffer, OAuthParameters oparams)
        {
            foreach (KeyValuePair<string, SortedSet<string>> key in oparams.getBaseParameters())
            {
                SortedSet<string> value = key.Value;
                parseSortedSetValues(buffer, key.Key, value);
                buffer.Append(COMMA);
            }
            buffer.Remove(buffer.Length - 1, 1);
            return buffer;
        }

        /// <summary>
        /// Helper method to build the comma delimited list of key/values in a sorted set
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="key"></param>
        /// <param name="paramap"></param>
        /// <returns></returns>
        private void parseSortedSetValues(StringBuilder buffer, string key, SortedSet<string> paramap)
        {
            foreach (string value in paramap.Keys)
            {
                buffer.Append(key).Append(EQUALS).Append(DOUBLE_QOUTE).Append(UrlEncodeRfc3986(value)).Append(DOUBLE_QOUTE);
            }
            //return;
        }

        /// <summary>
        /// Splits the responseParameters string into Key/Value pairs in the returned Dictionary 
        /// </summary>
        /// <param name="responseParameters"></param>
        /// <returns></returns>
        protected Dictionary<string, string> parseOAuthResponseParameters(string responseParameters)
        {
            if (responseParameters == null)
            {
                throw new MCApiRuntimeException(NULL_RESPONSE_PARAMETERS_ERROR);
            }

            Dictionary<string, string> result = new Dictionary<string, string>();
            string[] parameters = responseParameters.Split('&');

            foreach (string value in parameters)
            {
                string[] keyValue = value.Split('=');
                if (keyValue.Length == 2)
                {
                    result.Add(keyValue[0], keyValue[1]);
                }
            }
            // if the keyValue length is not 2 then they will be ignored
            return result;
        }

        /// <summary>
        /// Generates and signs the signature base string
        /// </summary>
        /// <param name="httpsURL"></param>
        /// <param name="requestMethod"></param>
        /// <param name="oparams"></param>
        /// <returns></returns>
        private string generateAndSignSignature(string httpsURL, string requestMethod, OAuthParameters oparams)
        {
            OAuthParameters sbsParams = new OAuthParameters();
            sbsParams.putAll(oparams.getBaseParameters());

            string realm = null;
            if (sbsParams.get(REALM) != EMPTY_STRING)
            {
                realm = sbsParams.get(REALM);
                sbsParams.remove(REALM, null);
            }
            var baseString = generateSignatureBaseString(httpsURL, requestMethod, sbsParams);
            _signatureBaseString = baseString;

            var signature = sign(baseString, privateKey);
            oparams.addParameter(OAUTH_SIGNATURE, signature);
            if (realm != null)
            {
                sbsParams.put(REALM, realm);
            }
            return signature;
        }

        /// <summary>
        /// Method to signthe signature base string. 
        /// </summary>
        /// <param name="baseString"></param>
        /// <param name="keyStore"></param>
        /// <returns></returns>
        private string sign(string baseString, AsymmetricAlgorithm keyStore)
        {
            byte[] baseStringBytes = encoder.GetBytes(baseString);


            using (var csp = (RSACryptoServiceProvider)keyStore)
            {
                try
                {
                    using (var sha1 = new SHA1Managed())
                    {
                        //UnicodeEncoding encoding = new UnicodeEncoding();
                        byte[] hash = sha1.ComputeHash(baseStringBytes);
                        byte[] signedHashValue = csp.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
                        return Convert.ToBase64String(signedHashValue);
                    }
                }
                catch (CryptographicException cex)
                {
                    throw new MCApiRuntimeException(cex.Message, cex);
                }
                catch (Exception ex)
                {
                    throw new MCApiRuntimeException(ex.Message, ex);
                }
            }
        }

        /// <summary>
        /// Generates the signature base string
        /// </summary>
        /// <param name="httpsURL"></param>
        /// <param name="requestMethod"></param>
        /// <param name="oparams"></param>
        /// <returns></returns>
        private string generateSignatureBaseString(string httpsURL, string requestMethod, OAuthParameters oparams)
        {
            Uri requestUri = parseUrl(httpsURL);
            var encodedBaseString = UrlEncodeRfc3986(requestMethod.ToUpper()) + AMP + UrlEncodeRfc3986(normalizeUrl(requestUri)) + AMP + UrlEncodeRfc3986(normalizeParameters(httpsURL, oparams));
            return encodedBaseString;
        }

        /// <summary>
        /// Normalizes the request URL before adding it to the signature base string
        /// </summary>
        /// <param name="uri"></param>
        /// <returns></returns>
        private static string normalizeUrl(Uri uri)
        {
            return uri.Scheme + COLON_2X_BACKSLASH + uri.Host + uri.AbsolutePath;
        }

        /// <summary>
        /// Normalize the OAuth parameters as they are added to the signature base string
        /// </summary>
        /// <param name="httpUrl"></param>
        /// <param name="requestParameters"></param>
        /// <returns></returns>
        private static string normalizeParameters(string httpUrl, OAuthParameters requestParameters)
        {
            // add the querystring to the base string (if one exists)
            if (httpUrl.IndexOf(QUESTION_MARK) > 0)
            {
                NameValueCollection queryParameters = HttpUtility.ParseQueryString(httpUrl.Substring(httpUrl.IndexOf(QUESTION_MARK) + 1));
                foreach (string key in queryParameters)
                {
                    requestParameters.put(key, UrlEncodeRfc3986(queryParameters[key]));
                }
            }
            // piece together the base string, encoding each key and value
            StringBuilder paramString = new StringBuilder();
            foreach (KeyValuePair<string, SortedSet<string>> kvp in requestParameters.getBaseParameters())
            {
                if (kvp.Value.Count == 0)
                {
                    continue; // Skip if key doesn't have any values
                }
                if (paramString.Length > 0)
                {
                    paramString.Append(AMP);
                }
                int tempCounter = 0;
                foreach (string value in kvp.Value.Keys)
                {
                    paramString.Append(UrlEncodeRfc3986(kvp.Key)).Append(EQUALS).Append((value));
                    if (tempCounter != kvp.Value.Count - 1)
                    {
                        paramString.Append(AMP);
                    }
                    tempCounter++;
                }
            }
            return paramString.ToString();
        }

        /// <summary>
        /// Converts a string URL to a Uri class
        /// </summary>
        /// <param name="httpsURL"></param>
        /// <returns></returns>
        private Uri parseUrl(string httpsURL)
        {
            // validate the request url
            if ((httpsURL == null) || (httpsURL.Length == 0))
            {
                throw new MCApiRuntimeException(NULL_PARAMETERS_ERROR);
            }
            return new Uri(httpsURL);
        }

        /// <summary>
        /// Reads the Http response and checks the response for errors.
        /// </summary>
        /// <param name="connection"></param>
        /// <returns></returns>
        private Dictionary<string, string> checkForErrorsAndReturnRepsonse(HttpWebRequest connection)
        {

            try
            {
                using (var webResp = (HttpWebResponse)connection.GetResponse())
                {
                    if ((int)webResp.StatusCode >= SC_MULTIPLE_CHOICES)
                    {
                        string message = readResponse(webResp);
                        // Cut the html off of the error message and leave the body
                        if (message.Contains(HTML_TAG))
                        {
                            message = message.Substring(message.IndexOf(BODY_OPENING_TAG) + 6, message.IndexOf(BODY_CLOSING_TAG));
                        }
                        throw new MCApiRuntimeException(message);
                    }

                    var responseMap = new Dictionary<string, string>();
                    responseMap.Add(MESSAGE, readResponse(webResp));
                    responseMap.Add(HTTP_CODE, webResp.StatusCode.ToString());

                    return responseMap;
                }

            }
            catch (WebException wex)
            {
                throw new MCApiRuntimeException(wex.Message, wex);
            }
        }

        /// <summary>
        /// Read the response from the Http reponse
        /// </summary>
        /// <param name="response"></param>
        /// <returns></returns>
        private string readResponse(HttpWebResponse response)
        {
            using (var dataStream = response.GetResponseStream())
            {
                if (dataStream != null)
                {
                    using (var reader = new StreamReader(dataStream))
                    {
                        string responseFromServer = reader.ReadToEnd();
                        return responseFromServer;
                    }
                }
                return string.Empty;
            }

        }

        /// <summary>
        /// Writes the body to an estiblished HttpWebRequest
        /// </summary>
        /// <param name="body"></param>
        /// <param name="con"></param>
        private void writeBodyToConnection(string body, HttpWebRequest con)
        {
            byte[] encodedBody = encoder.GetBytes(body);
            using (var newStream = con.GetRequestStream())
            {
                newStream.Write(encodedBody, 0, encodedBody.Length);
            }
        }

        /// <summary>
        /// Generates a 17 character Nonce
        /// </summary>
        /// <returns></returns>
        private static string getNonce()
        {
            int length = 17;
            var nonceString = new StringBuilder();
            for (int i = 0; i < length; i++)
            {
                nonceString.Append(validChars[random.Next(0, validChars.Length - 1)]);
            }
            return nonceString.ToString();
        }

        /// <summary>
        /// Generates a timestamp
        /// </summary>
        /// <returns></returns>
        private static string getTimestamp()
        {
            var _epochTime = (DateTime.UtcNow.Ticks - UNIX_EPOCH_TICKS) / 10000000;
            return _epochTime.ToString();
        }

        /// <summary>
        /// URL encodes to the RFC3986 specification
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string UrlEncodeRfc3986(string value)
        {
            StringBuilder escaped = new StringBuilder(Uri.EscapeDataString(value));
            for (int i = 0; i < UriRfc3986CharsToEscape.Length; i++)
            {
                escaped.Replace(UriRfc3986CharsToEscape[i], Uri.HexEscape(UriRfc3986CharsToEscape[i][0]));
            }
            return escaped.ToString();
        }
    }

}
