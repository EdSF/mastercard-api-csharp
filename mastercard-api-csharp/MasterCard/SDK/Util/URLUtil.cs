using System.Text;
using System.Web;

namespace MasterCard.SDK.Util
{
    public class URLUtil
    {
        public static string AddQueryParameter(string url, string descriptor, string value, bool considerIgnoreValue, string ignoreValue)
        {
            try
            {
                if (!considerIgnoreValue && value != null && !value.Equals("null") || (ignoreValue != null && value != null && !ignoreValue.Equals(value)))
                {
                    StringBuilder builder = new StringBuilder(url);
                    return builder.Append("&").Append(descriptor).Append("=").Append(Encode(value)).ToString();
                }
                else
                {
                    return url;
                }
            }
            catch (MCApiRuntimeException wex)
            {
                throw new MCApiRuntimeException(wex.Message, wex);
            }
        }

        public static string Encode(string value)
        {
            return HttpUtility.UrlEncode(value);
        }
    }
}
