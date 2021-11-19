using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace FursTester
{
    public class RSAPKCS1SHA256SignatureDescription : SignatureDescription
    {
        /// <summary>
        ///     Construct an RSAPKCS1SHA256SignatureDescription object. The default settings for this object
        ///     are:
        ///     <list type="bullet">
        ///         <item>Digest algorithm - <see cref="SHA256Managed" /></item>
        ///         <item>Key algorithm - <see cref="RSACryptoServiceProvider" /></item>
        ///         <item>Formatter algorithm - <see cref="RSAPKCS1SignatureFormatter" /></item>
        ///         <item>Deformatter algorithm - <see cref="RSAPKCS1SignatureDeformatter" /></item>
        ///     </list>
        /// </summary>
        public RSAPKCS1SHA256SignatureDescription()
        {
            KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
            DigestAlgorithm = typeof(SHA256Managed).FullName;   // Note - SHA256CryptoServiceProvider is not registered with CryptoConfig
            FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
            DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(key);
            deformatter.SetHashAlgorithm("SHA256");
            return deformatter;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm("SHA256");
            return formatter;
        }
    }
}
