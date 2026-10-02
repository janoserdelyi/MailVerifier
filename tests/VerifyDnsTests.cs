using System.Collections.Generic;
using System.Threading.Tasks;
using DNS.Protocol;
using Xunit;

namespace MailVerifier.Tests;

[Collection ("Dns")]
public class VerifyDnsTests
{
	public static TheoryData<string, string> MxLookups { get; } = new ()
	{
		{ "gmail.com", "1.1.1.1" },
		{ "gmail.com", "8.8.8.8" },
		{ "yahoo.com", "1.1.1.1" },
		{ "outlook.com", "8.8.8.8" },
	};

	public static TheoryData<string> ValidAddresses { get; } = new ()
	{
		"test@gmail.com",
		"test@yahoo.com",
		"test@outlook.com",
		"test@hotmail.com",
	};

	[Theory]
	[MemberData (nameof (MxLookups))]
	public async Task GetAnswersAsync_KnownDomain_ReturnsMxRecords (string domain, string dnsServer) {
		var response = await Verify.GetAnswersAsync (domain, RecordType.MX, dnsServer: dnsServer);
		Assert.NotNull (response);
		Assert.NotEmpty (response.AnswerRecords);
	}

	[Theory]
	[InlineData ("nonexistent-xyz99999.invalid", "1.1.1.1")]
	[InlineData ("nonexistent-xyz99999.invalid", "8.8.8.8")]
	public async Task GetAnswersAsync_NonexistentDomain_ReturnsNullOrNameError (string domain, string dnsServer) {
		var response = await Verify.GetAnswersAsync (domain, RecordType.MX, dnsServer: dnsServer);
		Assert.True (response == null || response.ResponseCode == ResponseCode.NameError);
	}

	[Theory]
	[MemberData (nameof (ValidAddresses))]
	public async Task GetMxDomainsAsync_ValidAddress_ReturnsMxRecords (string address) {
		IList<string> mxs = await Verify.GetMxDomainsAsync (address);
		Assert.NotNull (mxs);
		Assert.NotEmpty (mxs);
	}

	[Theory]
	[InlineData ("test@nonexistent-xyz99999.invalid")]
	public async Task GetMxDomainsAsync_NonexistentDomain_ReturnsEmptyList (string address) {
		IList<string> mxs = await Verify.GetMxDomainsAsync (address);
		Assert.NotNull (mxs);
		Assert.Empty (mxs);
	}

	[Theory]
	[MemberData (nameof (ValidAddresses))]
	public void GetMxDomains_ValidAddress_ReturnsMxRecords (string address) {
		IList<string> mxs = Verify.GetMxDomains (address);
		Assert.NotNull (mxs);
		Assert.NotEmpty (mxs);
	}

	[Theory]
	[InlineData ("test@nonexistent-xyz99999.invalid")]
	public void GetMxDomains_NonexistentDomain_ReturnsEmptyList (string address) {
		IList<string> mxs = Verify.GetMxDomains (address);
		Assert.NotNull (mxs);
		Assert.Empty (mxs);
	}
}
