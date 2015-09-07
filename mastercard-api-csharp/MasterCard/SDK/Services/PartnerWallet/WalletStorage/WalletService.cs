using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using MasterCard.SDK.Services.PartnerWallet.Domain.All;

namespace MasterCard.SDK.Services.PartnerWallet
{
    public class WalletService : Connector
    {
        private readonly Environments.Environment environment;

        private const string SANDBOX_URL = "https://sandbox.api.mastercard.com/masterpass/partner/v6/wallet-provider/<wallet_provider_id>/wallet/<wallet_id>?Format=XML";
        private const string PRODUCTION_URL = "https://api.mastercard.com/masterpass/partner/v6/wallet-provider/<wallet_provider_id>/wallet/<wallet_id>?Format=XML";
        private const string MTF_URL = "https://api.mastercard.com/mtf/masterpass/partner/v6/wallet-provider/<wallet_provider_id>/wallet/<wallet_id>?Format=XML";

        public WalletService(Environments.Environment environment, string consumerKey, AsymmetricAlgorithm privateKey)
            : base(consumerKey, privateKey)
        {
            this.environment = environment;
        }
            
        public string CreateWallet(String walletProviderId)
        {
            string response = "";
            Dictionary<string, string> responseMap = doRequest(GetURL("POST", walletProviderId, null), "POST", " ");
            responseMap.TryGetValue(MESSAGE, out response);
            return response;
        }

        public Wallet ReadWallet(String walletProviderId, String walletId)
        {
            string response = "";
            Dictionary<string, string> responseMap = doRequest(GetURL("GET", walletProviderId, walletId), "GET", null);
            responseMap.TryGetValue(MESSAGE, out response);
            return Serializer<Wallet>.Deserialize(response);
        }

        public void DeleteWallet(String walletProviderId, String walletId)
        {
            doRequest(GetURL("DELETE", walletProviderId, walletId), "DELETE", null);
        }

        private string GetURL(String method, String walletProviderId, String walletId)
        {
            string url;
            if (this.environment == Environments.Environment.PRODUCTION)
            {
                url = PRODUCTION_URL;
            }
            else if (this.environment == Environments.Environment.MTF)
            {
                url = MTF_URL;
            }
            else
            {
                url = SANDBOX_URL;
            }

            url = url.Replace("<wallet_provider_id>", walletProviderId.ToString());
            if ((!method.Equals("POST")) && walletId != null)
            {
                url = url.Replace("<wallet_id>", walletId.ToString());
            }
            else
            {
                url = url.Replace("/<wallet_id>", "");
            }

            return url;
        }
    }
}