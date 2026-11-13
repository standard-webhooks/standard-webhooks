using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using StandardWebhooks.Exceptions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;

namespace StandardWebhooks
{
    /// <summary>
    /// Verifies asymmetric (v2a) webhook signatures.
    /// </summary>
    public sealed class WebhookAsymmetric
    {
        private const string PUBLIC_KEY_PREFIX = "whpk_";
        private const string SIGNATURE_PREFIX = "v2a,";
        private const int SIGNATURE_LENGTH = 64;

        private readonly byte[][] publicKeys;
        private readonly Ed25519PublicKeyParameters[] publicKeyParameters;
        private readonly string endpointId;

        /// <summary>
        /// Creates a verifier for an endpoint's asymmetric signatures.
        /// </summary>
        /// <param name="endpointId">The endpoint ID assigned by the webhook producer.</param>
        /// <param name="publicKeys">
        /// The endpoint's public keys (<c>whpk_</c> prefixed), newest first. A signature made by any of them is
        /// accepted, so keys can be rotated by adding the new key to the start of the list. The first key is used
        /// for endpoint verification responses.
        /// </param>
        /// <exception cref="EmptyWebhookSecretException">No public keys were given.</exception>
        /// <exception cref="ArgumentException">A public key or the endpoint ID is invalid.</exception>
        public WebhookAsymmetric(string endpointId, IEnumerable<string> publicKeys)
        {
            var keys = publicKeys?.ToArray();
            if (keys == null || keys.Length == 0)
            {
                throw new EmptyWebhookSecretException("Missing webhook public keys");
            }
            if (String.IsNullOrEmpty(endpointId))
            {
                throw new ArgumentException("Missing endpoint ID", nameof(endpointId));
            }
            if (endpointId.Contains("."))
            {
                throw new ArgumentException("Endpoint ID must not contain '.'", nameof(endpointId));
            }

            this.publicKeys = keys.Select(ParsePublicKey).ToArray();
            this.publicKeyParameters = this.publicKeys.Select(key => new Ed25519PublicKeyParameters(key, 0)).ToArray();
            this.endpointId = endpointId;
        }

        private static byte[] ParsePublicKey(string publicKey)
        {
            if (publicKey == null || !publicKey.StartsWith(PUBLIC_KEY_PREFIX, StringComparison.Ordinal))
            {
                throw new ArgumentException($"Webhook public key must start with {PUBLIC_KEY_PREFIX}", "publicKeys");
            }

            byte[] key;
            try
            {
                key = Convert.FromBase64String(publicKey.Substring(PUBLIC_KEY_PREFIX.Length));
            }
            catch (FormatException e)
            {
                throw new ArgumentException("Webhook public key must be base64 encoded", "publicKeys", e);
            }

            if (key.Length != Ed25519PublicKeyParameters.KeySize)
            {
                throw new ArgumentException($"Webhook public key must be {Ed25519PublicKeyParameters.KeySize} bytes", "publicKeys");
            }
            return key;
        }

        public void Verify(string payload, WebHeaderCollection headers)
        {
            string msgId = headers.Get(Webhook.UNBRANDED_ID_HEADER_KEY);
            string msgSignature = headers.Get(Webhook.UNBRANDED_SIGNATURE_HEADER_KEY);
            string msgTimestamp = headers.Get(Webhook.UNBRANDED_TIMESTAMP_HEADER_KEY);
            if (String.IsNullOrEmpty(msgId) || String.IsNullOrEmpty(msgSignature) || String.IsNullOrEmpty(msgTimestamp))
            {
                throw new WebhookVerificationException("Missing Required Headers");
            }

            var timestamp = Webhook.VerifyTimestamp(msgTimestamp);

            VerifySignature(msgId, timestamp, payload, msgSignature);
        }

        /// <summary>
        /// Verifies the signature header against the given message, without checking the timestamp.
        /// </summary>
        internal void VerifySignature(string msgId, DateTimeOffset timestamp, string payload, string msgSignature)
        {
            var content = $"{this.endpointId}.{msgId}.{timestamp.ToUnixTimeSeconds().ToString()}.{payload}";
            byte[] digest;
            using (var sha256 = SHA256.Create())
            {
                digest = sha256.ComputeHash(Webhook.SafeUTF8Encoding.GetBytes(content));
            }

            foreach (string versionedSignature in msgSignature.Split(' '))
            {
                if (!versionedSignature.StartsWith(SIGNATURE_PREFIX, StringComparison.Ordinal))
                {
                    continue;
                }

                byte[] signature;
                try
                {
                    signature = Convert.FromBase64String(versionedSignature.Substring(SIGNATURE_PREFIX.Length));
                }
                catch (FormatException)
                {
                    continue;
                }
                if (signature.Length != SIGNATURE_LENGTH)
                {
                    continue;
                }

                foreach (var publicKey in this.publicKeyParameters)
                {
                    var verifier = new Ed25519Signer();
                    verifier.Init(false, publicKey);
                    verifier.BlockUpdate(digest, 0, digest.Length);
                    if (verifier.VerifySignature(signature))
                    {
                        return;
                    }
                }
            }
            throw new WebhookVerificationException("No matching signature found");
        }

        /// <summary>
        /// Calculates the response to an endpoint verification challenge, using the first (newest) public key.
        /// </summary>
        /// <param name="challenge">The value of the webhook-challenge request header.</param>
        /// <returns>The value for the webhook-challenge-response response header.</returns>
        public string EndpointVerificationResponse(string challenge)
        {
            return EndpointVerificationResponse(this.publicKeys[0], challenge);
        }

        /// <summary>
        /// Verifies the response to an endpoint verification challenge. The response is accepted if it was
        /// calculated with any of the public keys.
        /// </summary>
        /// <param name="challenge">The challenge sent in the webhook-challenge request header.</param>
        /// <param name="header">The value of the webhook-challenge-response response header.</param>
        public void VerifyEndpointVerificationResponse(string challenge, string header)
        {
            if (String.IsNullOrEmpty(challenge) || String.IsNullOrEmpty(header))
            {
                throw new WebhookVerificationException("Missing challenge response");
            }

            var found = false;
            foreach (var publicKey in this.publicKeys)
            {
                var expectedSignature = EndpointVerificationResponse(publicKey, challenge);
                found |= Utils.SecureCompare(expectedSignature, header);
            }

            if (!found)
            {
                throw new WebhookVerificationException("No matching signature found");
            }
        }

        private string EndpointVerificationResponse(byte[] publicKey, string challenge)
        {
            var endpointIdBytes = Webhook.SafeUTF8Encoding.GetBytes("." + this.endpointId);
            var endpointKey = new byte[publicKey.Length + endpointIdBytes.Length];
            Buffer.BlockCopy(publicKey, 0, endpointKey, 0, publicKey.Length);
            Buffer.BlockCopy(endpointIdBytes, 0, endpointKey, publicKey.Length, endpointIdBytes.Length);

            var signature = Convert.ToBase64String(Webhook.EndpointVerificationSignature(endpointKey, challenge));
            return $"{SIGNATURE_PREFIX}{signature}";
        }
    }
}
