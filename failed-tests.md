Tested with [test data version r1rv84](https://github.com/bcgit/bc-test-data/releases/tag/r1rv84).

Explicit test had been skipped.


 **Org.BouncyCastle.Tests/NistCertPathTest/TestFunction**

   Source: NistCertPathTest.cs line 5215
   Duration: 1,5 sec

  Message: 
  Expected string length 22 but was 3427. Strings differ at index 18.
  Expected: "NistCertPathTest: Okay"
  But was:  "NistCertPathTest: \nNISTCertPathTest --  1: \nNISTCertPathTest ..."
  -----------------------------^


  Stack Trace: 
NistCertPathTest.TestFunction() line 5219

1)    at Org.BouncyCastle.Tests.NistCertPathTest.TestFunction() in D:\Projects\solutions.kkk2.svn\trunk\POC\DotNet\ESIG\external\bc-csharp-72f926777638eb1ad5c2d091d671923ab47b02fc\crypto\test\src\test\NistCertPathTest.cs:line 5219


---

**Org.BouncyCastle.Cms.Tests/SignedDataTest/TestSha1WithRsaCounterSignature**

   Source: SignedDataTest.cs line 1306
   Duration: 85 ms

  Message: 
System.ArgumentException : Bad sequence size: 2
Parameter name: seq

  Stack Trace: 
SignerInfo.ctor(Asn1Sequence seq) line 69
SignerInfo.GetInstance(Object obj) line 48
<Select>d__14`2.MoveNext() line 140
SignerInformation.GetCounterSignatures() line 244
SignedDataTest.TestSha1WithRsaCounterSignature() line 1326
