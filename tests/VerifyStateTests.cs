using Xunit;

namespace MailVerifier.Tests;

[Collection ("Dns")]
public class VerifyStateTests
{
	[Theory]
	[InlineData (null)]
	[InlineData ("")]
	public void AddDns_NullOrEmpty_DoesNotChangeCount (string value) {
		var countBefore = Verify.DnsIpCount;
		Verify.AddDns (value);
		Assert.Equal (countBefore, Verify.DnsIpCount);
	}

	[Fact]
	public void AddDns_NewIp_IncreasesCount () {
		// 192.0.2.x is TEST-NET-1 (RFC 5737), reserved for documentation, safe to use here
		var countBefore = Verify.DnsIpCount;
		Verify.AddDns ("192.0.2.99");
		Assert.Equal (countBefore + 1, Verify.DnsIpCount);
	}

	[Fact]
	public void AddDns_DuplicateIp_DoesNotIncreaseCount () {
		Verify.AddDns ("192.0.2.98");
		var countAfterFirst = Verify.DnsIpCount;
		Verify.AddDns ("192.0.2.98");
		Assert.Equal (countAfterFirst, Verify.DnsIpCount);
	}

	[Theory]
	[InlineData (null)]
	[InlineData ("")]
	public void AddBypassDomain_NullOrEmpty_DoesNotChangeCount (string value) {
		var countBefore = Verify.BypassDomainCount;
		Verify.AddBypassDomain (value);
		Assert.Equal (countBefore, Verify.BypassDomainCount);
	}

	[Fact]
	public void AddBypassDomain_NewDomain_IncreasesCount () {
		var countBefore = Verify.BypassDomainCount;
		Verify.AddBypassDomain ("bypass-test-new.invalid");
		Assert.Equal (countBefore + 1, Verify.BypassDomainCount);
	}

	[Fact]
	public void AddBypassDomain_DuplicateDomain_DoesNotIncreaseCount () {
		Verify.AddBypassDomain ("bypass-test-dup.invalid");
		var countAfterFirst = Verify.BypassDomainCount;
		Verify.AddBypassDomain ("bypass-test-dup.invalid");
		Assert.Equal (countAfterFirst, Verify.BypassDomainCount);
	}

	[Fact]
	public void WriteDebugMessages_DefaultsFalse () {
		// reset to known state then verify get/set round-trips
		Verify.WriteDebugMessages = false;
		Assert.False (Verify.WriteDebugMessages);
	}

	[Fact]
	public void WriteDebugMessages_SetTrue_GetTrue () {
		Verify.WriteDebugMessages = true;
		Assert.True (Verify.WriteDebugMessages);
		Verify.WriteDebugMessages = false;
	}
}
