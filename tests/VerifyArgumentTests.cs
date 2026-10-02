using System;
using System.Threading.Tasks;
using Xunit;

namespace MailVerifier.Tests;

[Collection ("Dns")]
public class VerifyArgumentTests
{
	[Fact]
	public void GetMxDomains_NullAddress_ThrowsArgumentNullException () {
		Assert.Throws<ArgumentNullException> (() => Verify.GetMxDomains (null));
	}

	[Theory]
	[InlineData ("notanemail")]
	[InlineData ("noemail")]
	[InlineData ("nodomain")]
	public void GetMxDomains_NoAtSign_ThrowsArgumentException (string address) {
		Assert.Throws<ArgumentException> (() => Verify.GetMxDomains (address));
	}

	[Theory]
	[InlineData ("a@b")]
	[InlineData ("ab@c")]
	public void GetMxDomains_TooShort_ThrowsArgumentException (string address) {
		Assert.Throws<ArgumentException> (() => Verify.GetMxDomains (address));
	}

	[Fact]
	public async Task GetMxDomainsAsync_NullAddress_ThrowsArgumentNullException () {
		await Assert.ThrowsAsync<ArgumentNullException> (() => Verify.GetMxDomainsAsync (null));
	}

	[Theory]
	[InlineData ("notanemail")]
	[InlineData ("noemail")]
	[InlineData ("nodomain")]
	public async Task GetMxDomainsAsync_NoAtSign_ThrowsArgumentException (string address) {
		await Assert.ThrowsAsync<ArgumentException> (() => Verify.GetMxDomainsAsync (address));
	}

	[Theory]
	[InlineData ("a@b")]
	[InlineData ("ab@c")]
	public async Task GetMxDomainsAsync_TooShort_ThrowsArgumentException (string address) {
		await Assert.ThrowsAsync<ArgumentException> (() => Verify.GetMxDomainsAsync (address));
	}

	[Fact]
	public async Task Check_NullAddress_ThrowsArgumentNullException () {
		await Assert.ThrowsAsync<ArgumentNullException> (() => Verify.Check (null));
	}

	[Theory]
	[InlineData ("notanemail")]
	[InlineData ("noemail")]
	[InlineData ("nodomain")]
	public async Task Check_NoAtSign_ThrowsArgumentException (string address) {
		await Assert.ThrowsAsync<ArgumentException> (() => Verify.Check (address));
	}

	[Theory]
	[InlineData ("a@b")]
	[InlineData ("ab@c")]
	public async Task Check_TooShort_ThrowsArgumentException (string address) {
		await Assert.ThrowsAsync<ArgumentException> (() => Verify.Check (address));
	}
}
