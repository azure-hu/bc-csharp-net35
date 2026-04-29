using System;
using System.Collections.Generic;
using System.Linq;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// OcspListID ::=  SEQUENCE {
    ///		ocspResponses	SEQUENCE OF OcspResponsesID
    /// }
    /// </code>
    /// </remarks>
    public class OcspListID
        : Asn1Encodable
    {
        public static OcspListID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OcspListID ocspListID)
                return ocspListID;
            return new OcspListID(Asn1Sequence.GetInstance(obj));
        }

        public static OcspListID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspListID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static OcspListID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspListID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_ocspResponses;

        private OcspListID(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 1)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_ocspResponses = Asn1Sequence.GetInstance(seq[0]);
            m_ocspResponses.MapElements(OcspResponsesID.GetInstance); // Validate
        }

        public OcspListID(params OcspResponsesID[] ocspResponses)
        {
            m_ocspResponses = DerSequence.FromElements(ocspResponses);
        }

        public OcspListID(IEnumerable<OcspResponsesID> ocspResponses)
        {
            if (ocspResponses == null)
                throw new ArgumentNullException(nameof(ocspResponses));

#if NET35
            IEnumerable<Asn1Encodable> tmp_ocspResponses = new List<Asn1Encodable>(ocspResponses.Select(r => r as Asn1Encodable));
            m_ocspResponses = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(tmp_ocspResponses));
#else
            m_ocspResponses = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(ocspResponses));
#endif
        }

        public OcspListID(IReadOnlyCollection<OcspResponsesID> ocspResponses)
        {
            if (ocspResponses == null)
                throw new ArgumentNullException(nameof(ocspResponses));

#if NET35
            IReadOnlyCollection<Asn1Encodable> tmp_ocspResponses = new ListEx<Asn1Encodable>(ocspResponses.Select(r => r as Asn1Encodable));
            m_ocspResponses = DerSequence.FromCollection(tmp_ocspResponses);
#else
            m_ocspResponses = DerSequence.FromCollection(ocspResponses);
#endif
        }

        public OcspResponsesID[] GetOcspResponses() => m_ocspResponses.MapElements(OcspResponsesID.GetInstance);

        public override Asn1Object ToAsn1Object() => DerSequence.FromElement(m_ocspResponses);
    }
}
