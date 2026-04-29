using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// <code>
    /// OtherSigningCertificate ::= SEQUENCE {
    /// 	certs		SEQUENCE OF OtherCertID,
    /// 	policies	SEQUENCE OF PolicyInformation OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public class OtherSigningCertificate
        : Asn1Encodable
    {
        public static OtherSigningCertificate GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OtherSigningCertificate otherSigningCertificate)
                return otherSigningCertificate;
            return new OtherSigningCertificate(Asn1Sequence.GetInstance(obj));
        }

        public static OtherSigningCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherSigningCertificate(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static OtherSigningCertificate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OtherSigningCertificate(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_certs;
        private readonly Asn1Sequence m_policies;

        private OtherSigningCertificate(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certs = Asn1Sequence.GetInstance(seq[0]);

            if (count > 1)
            {
                m_policies = Asn1Sequence.GetInstance(seq[1]);
            }
        }

        public OtherSigningCertificate(params OtherCertID[] certs)
            : this(certs, null)
        {
        }

        public OtherSigningCertificate(OtherCertID[] certs, params PolicyInformation[] policies)
        {
            m_certs = DerSequence.FromElements(certs);
            m_policies = DerSequence.FromElementsOptional(policies);
        }

        public OtherSigningCertificate(IEnumerable<OtherCertID> certs)
            : this(certs, null)
        {
        }

        public OtherSigningCertificate(IEnumerable<OtherCertID> certs, IEnumerable<PolicyInformation> policies)
        {
            if (certs == null)
                throw new ArgumentNullException(nameof(certs));

#if NET35
            IEnumerable<Asn1Encodable> tmp_certs = new List<Asn1Encodable>(policies.Select(c => c as Asn1Encodable));
            m_certs = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(tmp_certs));
#else
            m_certs = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(certs));
#endif

            if (policies != null)
            {
#if NET35
                IEnumerable<Asn1Encodable> tmp_policies = new List<Asn1Encodable>(policies.Select(p => p as Asn1Encodable));
                m_policies = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(tmp_policies));
#else
                m_policies = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(policies));
#endif
            }
        }

        public OtherSigningCertificate(IReadOnlyCollection<OtherCertID> certs,
            IReadOnlyCollection<PolicyInformation> policies)
        {
            if (certs == null)
                throw new ArgumentNullException(nameof(certs));

#if NET35
            IReadOnlyCollection<Asn1Encodable> tmp_certs = new ListEx<Asn1Encodable>(certs.Select(c => c as Asn1Encodable));
            m_certs = DerSequence.FromCollection(tmp_certs);
#else
            m_certs = DerSequence.FromCollection(certs);
#endif

            if (policies != null)
            {
#if NET35
                IReadOnlyCollection<Asn1Encodable> tmp_policies = new ListEx<Asn1Encodable>(policies.Select(p => p as Asn1Encodable));
                m_policies = DerSequence.FromCollection(tmp_policies);
#else
                m_policies = DerSequence.FromCollection(policies);
#endif
            }
        }

        public OtherCertID[] GetCerts() => m_certs.MapElements(OtherCertID.GetInstance);

        public PolicyInformation[] GetPolicies() => m_policies?.MapElements(PolicyInformation.GetInstance);

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_certs);
            v.AddOptional(m_policies);
            return new DerSequence(v);
        }
    }
}
